package main

import (
	"net/http"
	"strings"
)

// handleFirewallAgents returns all connected agents and their missions
// GET /api/firewall/agents
func handleFirewallAgents(w http.ResponseWriter, r *http.Request) {
	conns := agentTracker.GetConnections()

	type agentSummary struct {
		AgentID   string `json:"agent_id"`
		MissionID string `json:"mission_id"`
		PID       int    `json:"pid"`
		State     string `json:"state"`
		Query     string `json:"query"`
		Username  string `json:"username"`
	}

	var agents []agentSummary
	for _, c := range conns {
		a := agentSummary{
			PID:      c.PID,
			State:    c.State,
			Query:    c.Query,
			Username: c.Username,
		}
		if c.Identity != nil {
			a.AgentID = c.Identity.AgentID
			a.MissionID = c.Identity.MissionID
		}
		agents = append(agents, a)
	}

	writeJSON(w, map[string]interface{}{
		"agents": agents,
		"count":  len(agents),
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
