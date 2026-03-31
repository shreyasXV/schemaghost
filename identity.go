package main

import (
	"database/sql"
	"strings"
	"sync"
	"time"
)

// AgentIdentity represents a parsed agent identity from application_name
type AgentIdentity struct {
	AgentID   string `json:"agent_id"`
	MissionID string `json:"mission_id"`
	Raw       string `json:"raw"`
}

// AgentConnection represents an active agent connection from pg_stat_activity
type AgentConnection struct {
	PID             int            `json:"pid"`
	Identity        *AgentIdentity `json:"identity"`
	ApplicationName string         `json:"application_name"`
	Username        string         `json:"username"`
	ClientAddr      string         `json:"client_addr"`
	State           string         `json:"state"`
	Query           string         `json:"query"`
	QueryStart      *time.Time     `json:"query_start,omitempty"`
}

// AgentRecord is a persistent record of an agent that has connected
type AgentRecord struct {
	AgentID      string    `json:"agent_id"`
	LastMission  string    `json:"last_mission"`
	LastSeen     time.Time `json:"last_seen"`
	FirstSeen    time.Time `json:"first_seen"`
	Active       bool      `json:"active"`
	TotalQueries int       `json:"total_queries"`
	Violations   int       `json:"violations"`
	LastPID      int       `json:"last_pid"`
	LastClientIP string    `json:"last_client_ip"`
	Username     string    `json:"username"`
}

// AgentTracker tracks active and historical agent connections
type AgentTracker struct {
	mu          sync.RWMutex
	connections []AgentConnection
	agents      map[string]*AgentRecord // keyed by agent_id
}

func NewAgentTracker() *AgentTracker {
	return &AgentTracker{
		agents: make(map[string]*AgentRecord),
	}
}

// ParseAgentIdentity parses "agent:<agent_id>:mission:<mission_id>" format.
// Returns nil if not an agent connection.
func ParseAgentIdentity(appName string) *AgentIdentity {
	appName = strings.TrimSpace(appName)
	if !strings.HasPrefix(appName, "agent:") {
		return nil
	}

	parts := strings.SplitN(appName, ":", 4)
	// Expect: ["agent", "<agent_id>", "mission", "<mission_id>"]
	if len(parts) < 4 || parts[2] != "mission" {
		// Partial format: agent:<id> without mission
		if len(parts) >= 2 && parts[1] != "" {
			return &AgentIdentity{
				AgentID: parts[1],
				Raw:     appName,
			}
		}
		return nil
	}

	if parts[1] == "" || parts[3] == "" {
		return nil
	}

	return &AgentIdentity{
		AgentID:   parts[1],
		MissionID: parts[3],
		Raw:       appName,
	}
}

// Poll queries pg_stat_activity for active agent connections
func (at *AgentTracker) Poll(db *sql.DB) error {
	rows, err := db.Query(`
		SELECT pid, application_name, usename,
		       COALESCE(client_addr::text, ''),
		       COALESCE(state, ''),
		       COALESCE(query, ''),
		       query_start
		FROM pg_stat_activity
		WHERE application_name LIKE 'agent:%'
	`)
	if err != nil {
		return err
	}
	defer rows.Close()

	var conns []AgentConnection
	activeAgentIDs := make(map[string]bool)

	for rows.Next() {
		var c AgentConnection
		var queryStart sql.NullTime
		if err := rows.Scan(&c.PID, &c.ApplicationName, &c.Username,
			&c.ClientAddr, &c.State, &c.Query, &queryStart); err != nil {
			continue
		}
		if queryStart.Valid {
			c.QueryStart = &queryStart.Time
		}
		c.Identity = ParseAgentIdentity(c.ApplicationName)
		conns = append(conns, c)

		// Update persistent agent record
		if c.Identity != nil && c.Identity.AgentID != "" {
			activeAgentIDs[c.Identity.AgentID] = true
		}
	}

	if err := rows.Err(); err != nil {
		return err
	}

	at.mu.Lock()
	at.connections = conns

	// Update persistent records for active connections
	now := time.Now()
	for _, c := range conns {
		if c.Identity == nil || c.Identity.AgentID == "" {
			continue
		}
		agentID := c.Identity.AgentID
		rec, exists := at.agents[agentID]
		if !exists {
			rec = &AgentRecord{
				AgentID:   agentID,
				FirstSeen: now,
			}
			at.agents[agentID] = rec
		}
		rec.LastSeen = now
		rec.Active = true
		rec.LastPID = c.PID
		rec.LastClientIP = c.ClientAddr
		rec.Username = c.Username
		if c.Identity.MissionID != "" {
			rec.LastMission = c.Identity.MissionID
		}
		if c.State == "active" && c.Query != "" {
			rec.TotalQueries++
		}
	}

	// Mark agents not in current poll as inactive
	for agentID, rec := range at.agents {
		if !activeAgentIDs[agentID] {
			rec.Active = false
		}
	}

	at.mu.Unlock()
	return nil
}

// RecordViolation increments the violation count for an agent
func (at *AgentTracker) RecordViolation(agentID string) {
	at.mu.Lock()
	defer at.mu.Unlock()
	if rec, exists := at.agents[agentID]; exists {
		rec.Violations++
	} else {
		at.agents[agentID] = &AgentRecord{
			AgentID:    agentID,
			FirstSeen:  time.Now(),
			LastSeen:   time.Now(),
			Violations: 1,
		}
	}
}

// GetConnections returns all currently active agent connections
func (at *AgentTracker) GetConnections() []AgentConnection {
	at.mu.RLock()
	defer at.mu.RUnlock()
	result := make([]AgentConnection, len(at.connections))
	copy(result, at.connections)
	return result
}

// GetAgentConnections returns connections for a specific agent
func (at *AgentTracker) GetAgentConnections(agentID string) []AgentConnection {
	at.mu.RLock()
	defer at.mu.RUnlock()
	var result []AgentConnection
	for _, c := range at.connections {
		if c.Identity != nil && c.Identity.AgentID == agentID {
			result = append(result, c)
		}
	}
	return result
}

// GetAllAgents returns all known agents (active and inactive)
func (at *AgentTracker) GetAllAgents() []AgentRecord {
	at.mu.RLock()
	defer at.mu.RUnlock()
	result := make([]AgentRecord, 0, len(at.agents))
	for _, rec := range at.agents {
		result = append(result, *rec)
	}
	return result
}

// GetAgent returns a specific agent record
func (at *AgentTracker) GetAgent(agentID string) *AgentRecord {
	at.mu.RLock()
	defer at.mu.RUnlock()
	if rec, exists := at.agents[agentID]; exists {
		cp := *rec
		return &cp
	}
	return nil
}
