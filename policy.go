package main

import (
	"database/sql"
	"fmt"
	"log"
	"os"
	"regexp"
	"strings"
	"sync"
	"time"

	"gopkg.in/yaml.v3"
)

// PolicyConfig is the top-level policies.yaml structure
type PolicyConfig struct {
	DefaultPolicy    string                 `yaml:"default_policy" json:"default_policy"`
	BlockedFunctions []string               `yaml:"blocked_functions" json:"blocked_functions"`
	Agents           map[string]AgentPolicy `yaml:"agents" json:"agents"`
	Unidentified     UnidentifiedPolicy     `yaml:"unidentified" json:"unidentified"`
}

// AgentPolicy defines rules for a specific agent
type AgentPolicy struct {
	Description       string                   `yaml:"description" json:"description"`
	AuthToken         string                   `yaml:"auth_token" json:"-"`
	Missions          map[string]MissionPolicy `yaml:"missions" json:"missions"`
	BlockedOperations []string                 `yaml:"blocked_operations" json:"blocked_operations"`
	BlockedTables     []string                 `yaml:"blocked_tables" json:"blocked_tables"`
	AllowedFunctions  []string                 `yaml:"allowed_functions" json:"allowed_functions"`
}

// MissionPolicy defines per-mission table/operation access
// MissionPolicy defines per-mission table/operation access.
//
// Enforcement behavior (proxy mode):
//   - max_rows: per-statement circuit breaker. Counts DataRow wire messages;
//     terminates connection when exceeded. Client receives rows up to the limit
//     plus an ErrorResponse. Resets on ReadyForQuery ('Z').
//   - max_query_time_ms: per-statement timeout. Starts when query is forwarded
//     to upstream; kills connection via sync.Once shutdown if exceeded.
//     Resets on ReadyForQuery ('Z'). Per-transaction timing is not yet supported.
type MissionPolicy struct {
	Tables         []string `yaml:"tables" json:"tables"`
	MaxRows        int      `yaml:"max_rows" json:"max_rows"`
	MaxQueryTimeMs int      `yaml:"max_query_time_ms" json:"max_query_time_ms"`
	Conditions     []string `yaml:"conditions" json:"conditions"`
}

// UnidentifiedPolicy handles connections without agent: prefix
type UnidentifiedPolicy struct {
	Policy string `yaml:"policy" json:"policy"` // monitor | deny | allow
}

// PolicyViolation records a policy breach
type PolicyViolation struct {
	AgentID   string    `json:"agent_id"`
	MissionID string    `json:"mission_id"`
	Query     string    `json:"query"`
	Reason    string    `json:"reason"`
	Table     string    `json:"table"`
	Operation string    `json:"operation"`
	PID       int       `json:"pid"`
	Action    string    `json:"action"` // "blocked" or "monitored"
	Timestamp time.Time `json:"timestamp"`
}

// PolicyEngine manages policy loading, enforcement, and violation tracking
type PolicyEngine struct {
	mu          sync.RWMutex
	config      *PolicyConfig
	violations  []PolicyViolation
	enforcement string // "enforce" | "monitor"
	filePath    string
}

func NewPolicyEngine() *PolicyEngine {
	filePath := os.Getenv("POLICY_FILE")
	if filePath == "" {
		filePath = "./policies.yaml"
	}
	enforcement := os.Getenv("POLICY_ENFORCEMENT")
	if enforcement == "" {
		enforcement = "monitor"
	}

	pe := &PolicyEngine{
		enforcement: enforcement,
		filePath:    filePath,
	}

	if err := pe.LoadFromFile(filePath); err != nil {
		if enforcement == "enforce" {
			log.Fatalf("FATAL: Policy file required in enforce mode but failed to load (%v). Refusing to start — fail-closed.", err)
		}
		log.Printf("Policy engine: no policies loaded (%v) — running in monitor mode without policy enforcement", err)
		pe.config = &PolicyConfig{
			DefaultPolicy: "allow",
			Agents:        make(map[string]AgentPolicy),
			Unidentified:  UnidentifiedPolicy{Policy: "allow"},
		}
	}

	return pe
}

// LoadFromFile reads and parses a policies.yaml file
func (pe *PolicyEngine) LoadFromFile(path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return fmt.Errorf("reading policy file: %w", err)
	}

	var cfg PolicyConfig
	if err := yaml.Unmarshal(data, &cfg); err != nil {
		return fmt.Errorf("parsing policy YAML: %w", err)
	}

	if cfg.Agents == nil {
		cfg.Agents = make(map[string]AgentPolicy)
	}

	pe.mu.Lock()
	pe.config = &cfg
	pe.mu.Unlock()

	log.Printf("Policy engine: loaded %d agent policies from %s (default: %s)", len(cfg.Agents), path, cfg.DefaultPolicy)
	return nil
}

// Reload hot-reloads the policy file
func (pe *PolicyEngine) Reload() error {
	return pe.LoadFromFile(pe.filePath)
}

// GetConfig returns the current policy config
func (pe *PolicyEngine) GetConfig() *PolicyConfig {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.config
}

// GetViolations returns all recorded violations
func (pe *PolicyEngine) GetViolations() []PolicyViolation {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	result := make([]PolicyViolation, len(pe.violations))
	copy(result, pe.violations)
	return result
}

// GetViolationsByAgent returns violations for a specific agent
func (pe *PolicyEngine) GetViolationsByAgent(agentID string) []PolicyViolation {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	var result []PolicyViolation
	for _, v := range pe.violations {
		if v.AgentID == agentID {
			result = append(result, v)
		}
	}
	return result
}

func (pe *PolicyEngine) addViolation(v PolicyViolation) {
	pe.mu.Lock()
	pe.violations = append(pe.violations, v)
	// Keep last 1000 violations
	if len(pe.violations) > 1000 {
		pe.violations = pe.violations[len(pe.violations)-1000:]
	}
	pe.mu.Unlock()
}

// CheckQuery evaluates a query against the loaded policies.
// Returns nil if allowed, a PolicyViolation if blocked/flagged.
func (pe *PolicyEngine) CheckQuery(identity *AgentIdentity, query string, pid int) *PolicyViolation {
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()

	if cfg == nil {
		return nil
	}

	// Parse query using AST (falls back to regex automatically)
	parsed := ParseQuery(query)
	operation := parsed.Operation
	tables := parsed.Tables
	functions := parsed.Functions

	// Unidentified connection — check BEFORE dereferencing identity
	if identity == nil {
		if cfg.Unidentified.Policy == "deny" {
			v := PolicyViolation{
				AgentID:   "unidentified",
				Query:     truncateQuery(query),
				Reason:    "unidentified_connection",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
			return &v
		}
		if cfg.Unidentified.Policy == "monitor" {
			v := PolicyViolation{
				AgentID:   "unidentified",
				Query:     truncateQuery(query),
				Reason:    "unidentified_connection_monitored",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
			return &v
		}
		return nil
	}

	agentPolicy, agentExists := cfg.Agents[identity.AgentID]

	// Agent not in policy
	if !agentExists {
		if cfg.DefaultPolicy == "deny" {
			return &PolicyViolation{
				AgentID:   identity.AgentID,
				MissionID: identity.MissionID,
				Query:     truncateQuery(query),
				Reason:    "agent_not_in_policy",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}
		return nil
	}

	// Check blocked operations (global for agent)
	for _, blocked := range agentPolicy.BlockedOperations {
		if strings.EqualFold(operation, blocked) {
			return &PolicyViolation{
				AgentID:   identity.AgentID,
				MissionID: identity.MissionID,
				Query:     truncateQuery(query),
				Reason:    "blocked_operation",
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}
	}

	// Check blocked tables (global for agent)
	for _, table := range tables {
		if isTableBlocked(table, agentPolicy.BlockedTables) {
			return &PolicyViolation{
				AgentID:   identity.AgentID,
				MissionID: identity.MissionID,
				Query:     truncateQuery(query),
				Reason:    "blocked_table",
				Table:     table,
				Operation: operation,
				PID:       pid,
				Action:    "pending",
				Timestamp: time.Now(),
			}
		}
	}

	// Check mission policy
	if identity.MissionID != "" {
		missionPolicy, missionExists := agentPolicy.Missions[identity.MissionID]
		if !missionExists {
			if cfg.DefaultPolicy == "deny" {
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "no_mission_policy",
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
			return nil
		}

		// Check tables against mission allowed list
		if len(missionPolicy.Tables) > 0 {
			for _, table := range tables {
				if !isTableAllowed(table, missionPolicy.Tables) {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "table_not_in_mission",
						Table:     table,
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			}
		}

		// Check "UPDATE must include WHERE clause" condition
		for _, cond := range missionPolicy.Conditions {
			condLower := strings.ToLower(cond)
			if strings.Contains(condLower, "update must include where") {
				if strings.EqualFold(operation, "UPDATE") && !strings.Contains(strings.ToUpper(query), "WHERE") {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "condition_violated",
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			}
			if strings.Contains(condLower, "delete must include where") {
				if strings.EqualFold(operation, "DELETE") && !strings.Contains(strings.ToUpper(query), "WHERE") {
					return &PolicyViolation{
						AgentID:   identity.AgentID,
						MissionID: identity.MissionID,
						Query:     truncateQuery(query),
						Reason:    "condition_violated",
						Operation: operation,
						PID:       pid,
						Action:    "pending",
						Timestamp: time.Now(),
					}
				}
			}
		}
	}

	// ── Global function blocklist (checked last for most specific violation reason) ──
	if len(cfg.BlockedFunctions) > 0 && len(functions) > 0 {
		var agentAllowed map[string]bool
		if ap, ok := cfg.Agents[identity.AgentID]; ok && len(ap.AllowedFunctions) > 0 {
			agentAllowed = make(map[string]bool)
			for _, fn := range ap.AllowedFunctions {
				agentAllowed[strings.ToLower(fn)] = true
			}
		}

		for _, fn := range functions {
			fnLower := strings.ToLower(fn)
			if isFunctionBlocked(fnLower, cfg.BlockedFunctions) {
				if agentAllowed != nil && agentAllowed[fnLower] {
					continue
				}
				return &PolicyViolation{
					AgentID:   identity.AgentID,
					MissionID: identity.MissionID,
					Query:     truncateQuery(query),
					Reason:    "blocked_function:" + fn,
					Operation: operation,
					PID:       pid,
					Action:    "pending",
					Timestamp: time.Now(),
				}
			}
		}
	}

	// Default-deny for unrecognized operations
	if strings.EqualFold(operation, "UNKNOWN") {
		return &PolicyViolation{
			AgentID:   identity.AgentID,
			MissionID: identity.MissionID,
			Query:     truncateQuery(query),
			Reason:    "unrecognized_operation",
			Operation: operation,
			PID:       pid,
			Action:    "pending",
			Timestamp: time.Now(),
		}
	}

	return nil
}

// GetMaxRows returns the max_rows limit for an agent+mission (0 = unlimited).
func (pe *PolicyEngine) GetMaxRows(identity *AgentIdentity) int {
	if identity == nil {
		return 0
	}
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()
	if cfg == nil {
		return 0
	}
	agentPolicy, exists := cfg.Agents[identity.AgentID]
	if !exists {
		return 0
	}
	if identity.MissionID != "" {
		if mission, ok := agentPolicy.Missions[identity.MissionID]; ok && mission.MaxRows > 0 {
			return mission.MaxRows
		}
	}
	// Check default mission
	if mission, ok := agentPolicy.Missions["default"]; ok && mission.MaxRows > 0 {
		return mission.MaxRows
	}
	return 0
}

// GetMaxQueryTimeMs returns the max_query_time_ms limit for an agent+mission (0 = unlimited).
func (pe *PolicyEngine) GetMaxQueryTimeMs(identity *AgentIdentity) int {
	if identity == nil {
		return 0
	}
	pe.mu.RLock()
	cfg := pe.config
	pe.mu.RUnlock()
	if cfg == nil {
		return 0
	}
	agentPolicy, exists := cfg.Agents[identity.AgentID]
	if !exists {
		return 0
	}
	if identity.MissionID != "" {
		if mission, ok := agentPolicy.Missions[identity.MissionID]; ok && mission.MaxQueryTimeMs > 0 {
			return mission.MaxQueryTimeMs
		}
	}
	if mission, ok := agentPolicy.Missions["default"]; ok && mission.MaxQueryTimeMs > 0 {
		return mission.MaxQueryTimeMs
	}
	return 0
}

// GetEnforcement returns the current enforcement mode safely.
func (pe *PolicyEngine) GetEnforcement() string {
	pe.mu.RLock()
	defer pe.mu.RUnlock()
	return pe.enforcement
}

// EnforceOnConnection checks a live agent connection and takes action if violated
func (pe *PolicyEngine) EnforceOnConnection(db *sql.DB, conn AgentConnection) *PolicyViolation {
	if conn.Query == "" || conn.State != "active" {
		return nil
	}

	// Skip internal/system queries
	if isSystemQuery(conn.Query) {
		return nil
	}

	violation := pe.CheckQuery(conn.Identity, conn.Query, conn.PID)
	if violation == nil {
		return nil
	}

	// Set action based on enforcement mode
	if pe.GetEnforcement() == "enforce" {
		violation.Action = "blocked"
		// Try graceful cancel first
		var cancelled bool
		err := db.QueryRow("SELECT pg_cancel_backend($1)", conn.PID).Scan(&cancelled)
		if err != nil {
			log.Printf("Policy enforcement: pg_cancel_backend failed for pid %d: %v", conn.PID, err)
		} else if cancelled {
			log.Printf("Policy enforcement: cancelled pid %d (agent=%s, reason=%s)", conn.PID, violation.AgentID, violation.Reason)
		}
		// If cancel didn't work, escalate to terminate
		if !cancelled {
			_, err = db.Exec("SELECT pg_terminate_backend($1)", conn.PID)
			if err != nil {
				log.Printf("Policy enforcement: failed to terminate pid %d: %v", conn.PID, err)
			} else {
				log.Printf("Policy enforcement: terminated pid %d (agent=%s, reason=%s)", conn.PID, violation.AgentID, violation.Reason)
			}
		}
	} else {
		violation.Action = "monitored"
		log.Printf("Policy monitor: violation detected pid %d (agent=%s, reason=%s, query=%s)", conn.PID, violation.AgentID, violation.Reason, violation.Query)
	}

	pe.addViolation(*violation)

	// Update persistent agent tracker with violation count
	if agentTracker != nil && violation.AgentID != "" {
		agentTracker.RecordViolation(violation.AgentID)
	}

	return violation
}

// ── SQL Parsing (regex-based fallback for when AST fails) ──

// ExtractSQLOperationRegex returns the SQL operation type using regex (fallback)
func ExtractSQLOperationRegex(query string) string {
	normalized := strings.TrimSpace(query)
	// Strip leading comments
	for strings.HasPrefix(normalized, "/*") {
		idx := strings.Index(normalized, "*/")
		if idx < 0 {
			break
		}
		normalized = strings.TrimSpace(normalized[idx+2:])
	}
	// Skip SET statements (e.g., SET application_name = ...; SELECT ...)
	upper := strings.ToUpper(normalized)
	if strings.HasPrefix(upper, "SET ") {
		// Find the next statement after semicolon
		idx := strings.Index(normalized, ";")
		if idx >= 0 && idx+1 < len(normalized) {
			normalized = strings.TrimSpace(normalized[idx+1:])
			upper = strings.ToUpper(normalized)
		}
	}

	for _, op := range []string{"SELECT", "INSERT", "UPDATE", "DELETE", "DROP", "CREATE", "ALTER", "TRUNCATE", "GRANT", "COPY", "REASSIGN", "DO"} {
		if strings.HasPrefix(upper, op) {
			return op
		}
	}
	return "UNKNOWN"
}

var tableExtractRe = regexp.MustCompile(`(?i)\b(?:FROM|JOIN|INTO|UPDATE|TABLE)\s+([a-zA-Z_][a-zA-Z0-9_.]*(?:\s*,\s*[a-zA-Z_][a-zA-Z0-9_.]*)*)`)

// ExtractTablesRegex extracts table names from a SQL query using regex (fallback)
func ExtractTablesRegex(query string) []string {
	matches := tableExtractRe.FindAllStringSubmatch(query, -1)
	seen := make(map[string]bool)
	var tables []string

	for _, m := range matches {
		if len(m) < 2 {
			continue
		}
		// Split on commas for "FROM t1, t2" syntax
		parts := strings.Split(m[1], ",")
		for _, part := range parts {
			tbl := strings.TrimSpace(part)
			// Strip alias (take first word only)
			fields := strings.Fields(tbl)
			if len(fields) > 0 {
				tbl = fields[0]
			}
			tbl = strings.ToLower(tbl)
			// Skip known non-tables
			if tbl == "" || tbl == "set" || tbl == "values" || tbl == "(" {
				continue
			}
			if !seen[tbl] {
				seen[tbl] = true
				tables = append(tables, tbl)
			}
		}
	}
	return tables
}

// ── Helpers ──

func isTableBlocked(table string, blockedList []string) bool {
	tableLower := strings.ToLower(table)
	for _, blocked := range blockedList {
		blockedLower := strings.ToLower(blocked)
		if strings.HasSuffix(blockedLower, ".*") {
			// Wildcard: "pg_catalog.*" matches any pg_catalog.xxx
			prefix := strings.TrimSuffix(blockedLower, "*")
			if strings.HasPrefix(tableLower, prefix) {
				return true
			}
		} else if tableLower == blockedLower {
			return true
		}
	}
	return false
}

func isTableAllowed(table string, allowedList []string) bool {
	tableLower := strings.ToLower(table)
	for _, allowed := range allowedList {
		// Mission tables use format "schema.table: [ops]" or just "schema.table"
		allowedClean := strings.Split(allowed, ":")[0]
		allowedClean = strings.TrimSpace(strings.ToLower(allowedClean))
		if tableLower == allowedClean {
			return true
		}
		// Also match without schema prefix
		if !strings.Contains(tableLower, ".") && strings.HasSuffix(allowedClean, "."+tableLower) {
			return true
		}
	}
	return false
}

func isSystemQuery(query string) bool {
	upper := strings.ToUpper(strings.TrimSpace(query))
	// For multi-statement queries (SET ...; SELECT ...), check the non-SET part
	if strings.HasPrefix(upper, "SET ") && strings.Contains(upper, ";") {
		idx := strings.Index(upper, ";")
		rest := strings.TrimSpace(upper[idx+1:])
		if rest != "" {
			return false // Has a real query after SET
		}
	}
	systemPrefixes := []string{
		"SET ", "SHOW ", "BEGIN", "COMMIT", "ROLLBACK",
		"LISTEN", "NOTIFY", "DISCARD", "RESET", "DEALLOCATE",
	}
	for _, prefix := range systemPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	// Skip pg_stat queries (our own polling)
	if strings.Contains(upper, "PG_STAT_") || strings.Contains(upper, "PG_DATABASE_SIZE") {
		return true
	}
	return false
}

func truncateQuery(q string) string {
	if len(q) > 200 {
		return q[:200] + "..."
	}
	return q
}

// isFunctionBlocked checks if a function name is in the blocklist
func isFunctionBlocked(fn string, blockedList []string) bool {
	for _, blocked := range blockedList {
		if strings.EqualFold(fn, blocked) {
			return true
		}
		// Also match schema-qualified: "pg_catalog.pg_sleep" matches "pg_sleep"
		if strings.Contains(fn, ".") {
			parts := strings.SplitN(fn, ".", 2)
			if strings.EqualFold(parts[len(parts)-1], blocked) {
				return true
			}
		}
	}
	return false
}
