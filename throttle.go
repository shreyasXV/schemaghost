package main

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strconv"
	"sync"
	"time"
)

// ThrottleAction represents the action to take on a long-running query
type ThrottleAction string

const (
	ActionCancel    ThrottleAction = "cancel"
	ActionTerminate ThrottleAction = "terminate"
)

// ThrottleEvent records a throttle action taken
type ThrottleEvent struct {
	Timestamp     time.Time `json:"timestamp"`
	TenantID      string    `json:"tenant_id"`
	PID           int       `json:"pid"`
	QueryDuration float64   `json:"query_duration_ms"`
	Action        string    `json:"action"`
	Query         string    `json:"query"`
}

// ThrottleConfig holds runtime-configurable throttle settings
type ThrottleConfig struct {
	Enabled              bool    `json:"enabled"`
	MaxQueryTimeMs       float64 `json:"max_query_time_ms"`
	MaxConnectionsTenant int     `json:"max_connections_per_tenant"`
	Action               string  `json:"action"`
	GracePeriodMs        int     `json:"grace_period_ms"`
}

// Throttler auto-throttles long-running queries and connection-heavy tenants
type Throttler struct {
	mu     sync.RWMutex
	config ThrottleConfig
	events []ThrottleEvent
	slack  *SlackNotifier
}

// NewThrottler creates a Throttler with config from env vars
func NewThrottler(slack *SlackNotifier) *Throttler {
	enabled := false
	if v := os.Getenv("THROTTLE_ENABLED"); v == "true" || v == "1" {
		enabled = true
	}

	maxQueryTimeMs := 30000.0
	if v := os.Getenv("THROTTLE_MAX_QUERY_TIME_MS"); v != "" {
		if f, err := strconv.ParseFloat(v, 64); err == nil {
			maxQueryTimeMs = f
		}
	}

	maxConns := 50
	if v := os.Getenv("THROTTLE_MAX_CONNECTIONS_PER_TENANT"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			maxConns = n
		}
	}

	action := "cancel"
	if v := os.Getenv("THROTTLE_ACTION"); v == "terminate" {
		action = "terminate"
	}

	gracePeriodMs := 5000
	if v := os.Getenv("THROTTLE_GRACE_PERIOD_MS"); v != "" {
		if n, err := strconv.Atoi(v); err == nil {
			gracePeriodMs = n
		}
	}

	return &Throttler{
		config: ThrottleConfig{
			Enabled:              enabled,
			MaxQueryTimeMs:       maxQueryTimeMs,
			MaxConnectionsTenant: maxConns,
			Action:               action,
			GracePeriodMs:        gracePeriodMs,
		},
		slack: slack,
	}
}

// activeQuery represents a running query from pg_stat_activity
type activeQuery struct {
	PID           int
	TenantID      string
	DurationMs    float64
	Query         string
	StateChange   time.Time
}

// Evaluate checks pg_stat_activity for long-running queries and connection limits
func (t *Throttler) Evaluate(database *sql.DB, d *Detector) {
	t.mu.RLock()
	cfg := t.config
	t.mu.RUnlock()

	if !cfg.Enabled {
		return
	}

	// Query pg_stat_activity for active queries with duration
	rows, err := database.Query(`
		SELECT pid,
			   COALESCE(query, ''),
			   EXTRACT(EPOCH FROM (now() - query_start)) * 1000 AS duration_ms,
			   COALESCE(state_change, now())
		FROM pg_stat_activity
		WHERE state = 'active'
		  AND pid != pg_backend_pid()
		  AND query NOT LIKE '%pg_stat_activity%'
		  AND query_start IS NOT NULL
		ORDER BY query_start ASC
	`)
	if err != nil {
		log.Printf("Throttler: failed to query pg_stat_activity: %v", err)
		return
	}
	defer rows.Close()

	var queries []activeQuery
	for rows.Next() {
		var aq activeQuery
		if err := rows.Scan(&aq.PID, &aq.Query, &aq.DurationMs, &aq.StateChange); err != nil {
			continue
		}
		// Attribute tenant
		aq.TenantID = extractTenantFromQuery(aq.Query, d)
		queries = append(queries, aq)
	}

	// 1. Kill queries exceeding max query time
	for _, aq := range queries {
		if aq.DurationMs >= cfg.MaxQueryTimeMs {
			t.throttleQuery(database, aq, cfg)
		}
	}

	// 2. Check per-tenant connection limits
	tenantConns := make(map[string][]activeQuery)
	for _, aq := range queries {
		tenantConns[aq.TenantID] = append(tenantConns[aq.TenantID], aq)
	}

	for tenantID, tqs := range tenantConns {
		if len(tqs) > cfg.MaxConnectionsTenant {
			// Cancel oldest queries first (they're already sorted ASC by query_start)
			excess := len(tqs) - cfg.MaxConnectionsTenant
			for i := 0; i < excess; i++ {
				t.cancelQuery(database, tqs[i], tenantID, "connection_limit")
			}
		}
	}
}

// throttleQuery cancels or terminates a single query based on config
func (t *Throttler) throttleQuery(database *sql.DB, aq activeQuery, cfg ThrottleConfig) {
	// First attempt: cancel
	cancelled := t.cancelQuery(database, aq, aq.TenantID, "long_running_cancel")
	if !cancelled {
		return
	}

	// If action is terminate, or if cancel + grace period, escalate
	if cfg.Action == "terminate" {
		// Wait grace period then check if still running
		go func(pid int, tenantID string, query string, durationMs float64) {
			time.Sleep(time.Duration(cfg.GracePeriodMs) * time.Millisecond)

			var stillRunning bool
			err := database.QueryRow(`SELECT EXISTS(SELECT 1 FROM pg_stat_activity WHERE pid = $1 AND state = 'active')`, pid).Scan(&stillRunning)
			if err != nil || !stillRunning {
				return
			}

			// Escalate to terminate
			var terminated bool
			err = database.QueryRow(`SELECT pg_terminate_backend($1)`, pid).Scan(&terminated)
			if err != nil {
				log.Printf("Throttler: pg_terminate_backend(%d) error: %v", pid, err)
				return
			}

			truncatedQuery := query
			if len(truncatedQuery) > 200 {
				truncatedQuery = truncatedQuery[:200] + "..."
			}

			event := ThrottleEvent{
				Timestamp:     time.Now(),
				TenantID:      tenantID,
				PID:           pid,
				QueryDuration: durationMs,
				Action:        "terminate",
				Query:         truncatedQuery,
			}
			t.addEvent(event)
			log.Printf("Throttler: TERMINATED pid=%d tenant=%s duration=%.0fms", pid, tenantID, durationMs)
			t.notifySlack(event)
		}(aq.PID, aq.TenantID, aq.Query, aq.DurationMs)
	}
}

// cancelQuery issues pg_cancel_backend and records the event
func (t *Throttler) cancelQuery(database *sql.DB, aq activeQuery, tenantID, reason string) bool {
	var cancelled bool
	err := database.QueryRow(`SELECT pg_cancel_backend($1)`, aq.PID).Scan(&cancelled)
	if err != nil {
		log.Printf("Throttler: pg_cancel_backend(%d) error: %v", aq.PID, err)
		return false
	}

	truncatedQuery := aq.Query
	if len(truncatedQuery) > 200 {
		truncatedQuery = truncatedQuery[:200] + "..."
	}

	event := ThrottleEvent{
		Timestamp:     time.Now(),
		TenantID:      tenantID,
		PID:           aq.PID,
		QueryDuration: aq.DurationMs,
		Action:        reason,
		Query:         truncatedQuery,
	}
	t.addEvent(event)
	log.Printf("Throttler: CANCELLED pid=%d tenant=%s duration=%.0fms reason=%s", aq.PID, tenantID, aq.DurationMs, reason)
	t.notifySlack(event)
	return true
}

// addEvent appends a ThrottleEvent, keeping at most 100
func (t *Throttler) addEvent(e ThrottleEvent) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.events = append(t.events, e)
	if len(t.events) > 100 {
		t.events = t.events[len(t.events)-100:]
	}
}

// notifySlack sends a throttle event to Slack
func (t *Throttler) notifySlack(e ThrottleEvent) {
	if t.slack == nil {
		return
	}
	title := fmt.Sprintf("[SchemaGhost] Throttle: %s on tenant '%s'", e.Action, e.TenantID)
	text := fmt.Sprintf("PID: `%d` | Duration: `%.0fms` | Action: `%s`\nQuery: `%s`",
		e.PID, e.QueryDuration, e.Action, e.Query)
	color := "#e53e3e" // red
	if e.Action == "long_running_cancel" || e.Action == "connection_limit" {
		color = "#f5c542" // yellow
	}
	payload := slackPayload(title, text, color)
	t.slack.send(payload)
}

// GetEvents returns a copy of recent throttle events
func (t *Throttler) GetEvents() []ThrottleEvent {
	t.mu.RLock()
	defer t.mu.RUnlock()
	result := make([]ThrottleEvent, len(t.events))
	copy(result, t.events)
	return result
}

// GetConfig returns the current config
func (t *Throttler) GetConfig() ThrottleConfig {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return t.config
}

// SetConfig updates runtime config
func (t *Throttler) SetConfig(cfg ThrottleConfig) {
	t.mu.Lock()
	defer t.mu.Unlock()
	t.config = cfg
}

// ── HTTP Handlers ──────────────────────────────────────────────────────

func handleThrottleStatus(w http.ResponseWriter, r *http.Request) {
	if throttler == nil {
		writeJSON(w, map[string]interface{}{"enabled": false})
		return
	}
	cfg := throttler.GetConfig()
	events := throttler.GetEvents()

	// Count active throttles (events in last 60s)
	activeCount := 0
	cutoff := time.Now().Add(-60 * time.Second)
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			activeCount++
		}
	}

	writeJSON(w, map[string]interface{}{
		"enabled":          cfg.Enabled,
		"config":           cfg,
		"recent_events":    events,
		"active_throttles": activeCount,
	})
}

func handleThrottleConfig(w http.ResponseWriter, r *http.Request) {
	if throttler == nil {
		http.Error(w, "throttler not initialized", http.StatusServiceUnavailable)
		return
	}

	switch r.Method {
	case http.MethodGet:
		writeJSON(w, throttler.GetConfig())

	case http.MethodPost:
		var cfg ThrottleConfig
		if err := json.NewDecoder(r.Body).Decode(&cfg); err != nil {
			http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
			return
		}
		// Validate action
		if cfg.Action != "cancel" && cfg.Action != "terminate" {
			cfg.Action = "cancel"
		}
		if cfg.MaxQueryTimeMs <= 0 {
			cfg.MaxQueryTimeMs = 30000
		}
		if cfg.MaxConnectionsTenant <= 0 {
			cfg.MaxConnectionsTenant = 50
		}
		if cfg.GracePeriodMs <= 0 {
			cfg.GracePeriodMs = 5000
		}
		throttler.SetConfig(cfg)
		log.Printf("Throttler: config updated enabled=%v max_query=%0.fms max_conns=%d action=%s",
			cfg.Enabled, cfg.MaxQueryTimeMs, cfg.MaxConnectionsTenant, cfg.Action)
		writeJSON(w, cfg)

	default:
		http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
	}
}
