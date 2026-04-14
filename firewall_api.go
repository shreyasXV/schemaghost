package main

import (
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"time"
)

// handleFirewallAgents returns all known agents (active and historical)
// GET /api/firewall/agents
func handleFirewallAgents(w http.ResponseWriter, r *http.Request) {
	// Return persistent agent records (active + inactive)
	allAgents := agentTracker.GetAllAgents()

	// Also include live connections for active agents
	conns := agentTracker.GetConnections()

	type agentResponse struct {
		AgentID      string  `json:"agent_id"`
		LastMission  string  `json:"last_mission"`
		Active       bool    `json:"active"`
		FirstSeen    string  `json:"first_seen"`
		LastSeen     string  `json:"last_seen"`
		TotalQueries int     `json:"total_queries"`
		Violations   int     `json:"violations"`
		LastPID      int     `json:"last_pid"`
		LastClientIP string  `json:"last_client_ip"`
		Username     string  `json:"username"`
	}

	agents := make([]agentResponse, 0, len(allAgents))
	for _, rec := range allAgents {
		agents = append(agents, agentResponse{
			AgentID:      rec.AgentID,
			LastMission:  rec.LastMission,
			Active:       rec.Active,
			FirstSeen:    rec.FirstSeen.UTC().Format(time.RFC3339),
			LastSeen:     rec.LastSeen.UTC().Format(time.RFC3339),
			TotalQueries: rec.TotalQueries,
			Violations:   rec.Violations,
			LastPID:      rec.LastPID,
			LastClientIP: rec.LastClientIP,
			Username:     rec.Username,
		})
	}

	writeJSON(w, map[string]interface{}{
		"agents":             agents,
		"count":              len(agents),
		"active_connections": len(conns),
	})
}

// handleFirewallAgentQueries returns queries by a specific agent
// GET /api/firewall/agents/{agent_id}/queries
func handleFirewallAgentQueries(w http.ResponseWriter, r *http.Request) {
	// Parse agent_id from path: /api/firewall/agents/{agent_id}/queries
	path := strings.TrimPrefix(r.URL.Path, "/api/firewall/agents/")
	parts := strings.SplitN(path, "/", 2)
	if len(parts) == 0 || parts[0] == "" {
		http.Error(w, "agent_id required", http.StatusBadRequest)
		return
	}
	agentID := parts[0]

	conns := agentTracker.GetAgentConnections(agentID)
	writeJSON(w, map[string]interface{}{
		"agent_id":    agentID,
		"connections": conns,
		"count":       len(conns),
	})
}

// handlePolicies returns the current loaded policies
// GET /api/policies
func handlePolicies(w http.ResponseWriter, r *http.Request) {
	cfg := policyEngine.GetConfig()
	writeJSON(w, cfg)
}

// handlePoliciesReload hot-reloads the policies.yaml file
// POST /api/policies/reload
func handlePoliciesReload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	if err := policyEngine.Reload(); err != nil {
		writeJSON(w, map[string]interface{}{
			"status": "error",
			"error":  err.Error(),
		})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":  "ok",
		"message": "Policies reloaded successfully",
	})
}

// handleViolations returns policy violations, optionally filtered by agent
// GET /api/violations
// GET /api/violations?agent=cursor-ai
func handleViolations(w http.ResponseWriter, r *http.Request) {
	agentFilter := r.URL.Query().Get("agent")

	var violations []PolicyViolation
	if agentFilter != "" {
		violations = policyEngine.GetViolationsByAgent(agentFilter)
	} else {
		violations = policyEngine.GetViolations()
	}

	// Return newest first
	reversed := make([]PolicyViolation, len(violations))
	for i, v := range violations {
		reversed[len(violations)-1-i] = v
	}

	writeJSON(w, map[string]interface{}{
		"violations": reversed,
		"count":      len(reversed),
	})
}

// handleAgentStats returns per-agent aggregated metrics
// GET /api/agents/stats
func handleAgentStats(w http.ResponseWriter, r *http.Request) {
	allAgents := agentTracker.GetAllAgents()

	costPerRow := 0.0001 // default $0.0001 per row

	type agentStats struct {
		AgentID        string  `json:"agent_id"`
		TotalQueries   int     `json:"total_queries"`
		TotalRows      int64   `json:"total_rows"`
		EstimatedCost  float64 `json:"estimated_cost"`
		TotalDurationMs float64 `json:"total_duration_ms"`
		AvgDurationMs  float64 `json:"avg_duration_ms"`
		Violations     int     `json:"violations"`
		Active         bool    `json:"active"`
		Paused         bool    `json:"paused"`
	}

	stats := make([]agentStats, 0, len(allAgents))
	for _, rec := range allAgents {
		avgDur := 0.0
		if rec.TotalQueries > 0 {
			avgDur = rec.TotalDurationMs / float64(rec.TotalQueries)
		}
		stats = append(stats, agentStats{
			AgentID:        rec.AgentID,
			TotalQueries:   rec.TotalQueries,
			TotalRows:      rec.TotalRows,
			EstimatedCost:  float64(rec.TotalRows) * costPerRow,
			TotalDurationMs: rec.TotalDurationMs,
			AvgDurationMs:  avgDur,
			Violations:     rec.Violations,
			Active:         rec.Active,
			Paused:         policyEngine.IsAgentPaused(rec.AgentID),
		})
	}

	writeJSON(w, map[string]interface{}{
		"agents":       stats,
		"count":        len(stats),
		"cost_per_row": costPerRow,
	})
}

// handleBlockRule adds a blocked query pattern to the agent's policy and persists it
// POST /api/rules/block
// Body: {"query_pattern": "...", "agent_id": "..."}
func handleBlockRule(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "POST required", http.StatusMethodNotAllowed)
		return
	}

	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "failed to read body"})
		return
	}

	var req struct {
		QueryPattern string `json:"query_pattern"`
		AgentID      string `json:"agent_id"`
	}
	if err := json.Unmarshal(body, &req); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "invalid JSON"})
		return
	}

	if req.QueryPattern == "" {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "query_pattern required"})
		return
	}

	// Extract tables from the query pattern to add to blocked_tables
	parsed := ParseQuery(req.QueryPattern)
	tables := parsed.Tables

	cfg := policyEngine.GetConfig()
	if cfg == nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": "no policy config loaded"})
		return
	}

	// Add tables to the agent's blocked_tables (or unidentified if no agent)
	policyEngine.mu.Lock()
	if req.AgentID != "" && req.AgentID != "unidentified" {
		agent, exists := cfg.Agents[req.AgentID]
		if !exists {
			agent = AgentPolicy{Description: "Auto-created by block rule"}
		}
		for _, t := range tables {
			if !isTableBlocked(t, agent.BlockedTables) {
				agent.BlockedTables = append(agent.BlockedTables, t)
			}
		}
		cfg.Agents[req.AgentID] = agent
	}
	policyEngine.mu.Unlock()

	// Persist to file and reload
	if err := policyEngine.SaveToFile(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}
	if err := policyEngine.Reload(); err != nil {
		writeJSON(w, map[string]interface{}{"status": "error", "error": err.Error()})
		return
	}

	writeJSON(w, map[string]interface{}{
		"status":         "ok",
		"message":        "Block rule applied and persisted",
		"blocked_tables": tables,
		"agent_id":       req.AgentID,
	})
}

// handlePauseAgent pauses or resumes an agent
// POST /api/agents/pause/{agent_id} — pause the agent
// DELETE /api/agents/pause/{agent_id} — resume the agent
// GET /api/agents/pause/{agent_id} — check pause status
func handlePauseAgent(w http.ResponseWriter, r *http.Request) {
	// Parse agent_id from path: /api/agents/pause/{agent_id}
	agentID := strings.TrimPrefix(r.URL.Path, "/api/agents/pause/")
	if agentID == "" {
		// Return list of all paused agents
		writeJSON(w, map[string]interface{}{
			"paused_agents": policyEngine.GetPausedAgents(),
		})
		return
	}

	switch r.Method {
	case http.MethodPost:
		policyEngine.SetAgentPaused(agentID, true)
		writeJSON(w, map[string]interface{}{
			"status":   "ok",
			"agent_id": agentID,
			"paused":   true,
			"message":  "Agent paused — all queries will be blocked",
		})
	case http.MethodDelete:
		policyEngine.SetAgentPaused(agentID, false)
		writeJSON(w, map[string]interface{}{
			"status":   "ok",
			"agent_id": agentID,
			"paused":   false,
			"message":  "Agent resumed",
		})
	case http.MethodGet:
		paused := policyEngine.IsAgentPaused(agentID)
		writeJSON(w, map[string]interface{}{
			"agent_id": agentID,
			"paused":   paused,
		})
	default:
		http.Error(w, "Method not allowed", http.StatusMethodNotAllowed)
	}
}
