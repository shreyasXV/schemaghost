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

// AgentTracker tracks active agent connections
type AgentTracker struct {
	mu          sync.RWMutex
	connections []AgentConnection
}

func NewAgentTracker() *AgentTracker {
	return &AgentTracker{}
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
	}

	at.mu.Lock()
	at.connections = conns
	at.mu.Unlock()
	return nil
}

// GetConnections returns all tracked agent connections
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
