package main

import (
	"net/http"
	"strings"
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
			FirstSeen:    rec.FirstSeen.Format("2006-01-02T15:04:05Z"),
			LastSeen:     rec.LastSeen.Format("2006-01-02T15:04:05Z"),
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
