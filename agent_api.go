package main

import (
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"time"
)

// handleAgentStatus returns a one-call overview for AI agents
func handleAgentStatus(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	activeAlerts := alertManager.GetActiveAlerts()

	// Count throttle events in last hour
	events := throttler.GetEvents()
	throttleCount := 0
	cutoff := time.Now().Add(-1 * time.Hour)
	for _, e := range events {
		if e.Timestamp.After(cutoff) {
			throttleCount++
		}
	}

	// Find noisy tenants (avg > 100ms)
	var noisy []map[string]interface{}
	for _, t := range data.Tenants {
		if t.AvgTimeMs > 100 {
			noisy = append(noisy, map[string]interface{}{
				"tenant_id":   t.TenantID,
				"avg_time_ms": t.AvgTimeMs,
				"queries":     t.Queries,
				"connections": t.Connections,
			})
		}
	}

	healthy := len(activeAlerts) == 0 && len(noisy) == 0

	summary := fmt.Sprintf("Database is %s. %d tenants monitored, %d active alerts, %d throttle events in the last hour.",
		statusWord(healthy), len(data.Tenants), len(activeAlerts), throttleCount)
	if len(noisy) > 0 {
		summary += fmt.Sprintf(" %d noisy tenant(s) detected.", len(noisy))
	}

	writeJSON(w, map[string]interface{}{
		"healthy":              healthy,
		"noisy_tenants":        noisy,
		"total_tenants":        len(data.Tenants),
		"active_alerts":        len(activeAlerts),
		"throttle_events_1h":   throttleCount,
		"cache_hit_ratio":      data.Overview.CacheHitRatio,
		"total_connections":    data.Overview.TotalConnections,
		"qps":                  data.Overview.QueriesPerSec,
		"summary":              summary,
	})
}

// handleAgentNoisy returns noisy tenants with actionable context
func handleAgentNoisy(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	costs := costEstimator.GetCosts()
	costMap := make(map[string]TenantCost)
	for _, c := range costs {
		costMap[c.TenantID] = c
	}

	// Calculate total query time for percentage
	var totalQueryTime float64
	for _, t := range data.Tenants {
		totalQueryTime += t.AvgTimeMs * float64(t.Queries)
	}

	var noisy []map[string]interface{}
	for _, t := range data.Tenants {
		if t.AvgTimeMs <= 100 {
			continue
		}
		tenantQueryTime := t.AvgTimeMs * float64(t.Queries)
		pct := 0.0
		if totalQueryTime > 0 {
			pct = tenantQueryTime / totalQueryTime * 100
		}

		entry := map[string]interface{}{
			"tenant_id":       t.TenantID,
			"avg_time_ms":     t.AvgTimeMs,
			"p99_ms":          t.P99Ms,
			"queries":         t.Queries,
			"connections":     t.Connections,
			"resource_pct":    fmt.Sprintf("%.1f%%", pct),
			"summary":         fmt.Sprintf("%s has avg query time %.0fms (%s of total resources), %d active connections", t.TenantID, t.AvgTimeMs, fmt.Sprintf("%.1f%%", pct), t.Connections),
		}
		if c, ok := costMap[t.TenantID]; ok {
			entry["monthly_cost"] = c.MonthlyCost
		}
		noisy = append(noisy, entry)
	}

	summary := fmt.Sprintf("%d noisy tenant(s) with avg query time above 100ms.", len(noisy))
	if len(noisy) == 0 {
		summary = "No noisy tenants detected. All tenants are within normal parameters."
	}

	writeJSON(w, map[string]interface{}{
		"noisy_tenants": noisy,
		"threshold_ms":  100,
		"summary":       summary,
	})
}

// handleAgentTenant returns tenant detail with plain-english summary
func handleAgentTenant(w http.ResponseWriter, r *http.Request) {
	// Extract tenant ID from /api/agents/tenant/{id}
	path := strings.TrimPrefix(r.URL.Path, "/api/agents/tenant/")
	tenantID := strings.TrimSuffix(path, "/")
	if tenantID == "" {
		http.Error(w, "tenant ID required", http.StatusBadRequest)
		return
	}

	// Handle POST for throttle action
	if r.Method == http.MethodPost {
		handleAgentTenantThrottle(w, r, tenantID)
		return
	}

	data := collector.GetData()

	// Calculate totals for percentage
	var totalQueryTime float64
	for _, t := range data.Tenants {
		totalQueryTime += t.AvgTimeMs * float64(t.Queries)
	}

	for _, t := range data.Tenants {
		if t.TenantID != tenantID {
			continue
		}
		tenantQueryTime := t.AvgTimeMs * float64(t.Queries)
		pct := 0.0
		if totalQueryTime > 0 {
			pct = tenantQueryTime / totalQueryTime * 100
		}

		cost := costEstimator.GetTenantCost(tenantID)

		summary := fmt.Sprintf("%s is consuming %.1f%% of database resources, avg query time %.0fms, %d active connections.",
			tenantID, pct, t.AvgTimeMs, t.Connections)
		if cost != nil {
			summary += fmt.Sprintf(" Estimated monthly cost: $%.2f.", cost.MonthlyCost)
		}

		writeJSON(w, map[string]interface{}{
			"tenant_id":    t.TenantID,
			"metrics":      t,
			"cost":         cost,
			"resource_pct": fmt.Sprintf("%.1f%%", pct),
			"summary":      summary,
		})
		return
	}

	http.Error(w, "tenant not found", http.StatusNotFound)
}

// handleAgentTenantThrottle handles POST /api/agents/tenant/{id}/throttle
func handleAgentTenantThrottle(w http.ResponseWriter, r *http.Request, tenantID string) {
	var body struct {
		Action string `json:"action"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		http.Error(w, "invalid JSON: "+err.Error(), http.StatusBadRequest)
		return
	}
	if body.Action == "" {
		body.Action = "cancel"
	}
	if body.Action != "cancel" && body.Action != "terminate" {
		http.Error(w, "action must be 'cancel' or 'terminate'", http.StatusBadRequest)
		return
	}

	result, err := mcpThrottleTenant(tenantID, body.Action)
	if err != nil {
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	resultMap := result.(map[string]interface{})
	affected := resultMap["queries_affected"].(int)
	summary := fmt.Sprintf("Executed %s on %d active queries for tenant %s.", body.Action, affected, tenantID)

	resultMap["summary"] = summary
	writeJSON(w, resultMap)
}

// handleAgentCosts returns simplified cost view
func handleAgentCosts(w http.ResponseWriter, r *http.Request) {
	costs := costEstimator.GetCosts()

	var totalMonthly float64
	for _, c := range costs {
		totalMonthly += c.MonthlyCost
	}

	var entries []map[string]interface{}
	for _, c := range costs {
		entries = append(entries, map[string]interface{}{
			"tenant_id":    c.TenantID,
			"monthly_cost": c.MonthlyCost,
			"daily_cost":   c.DailyCost,
			"proportion":   fmt.Sprintf("%.1f%%", c.QueryTimeProportion*100),
		})
	}

	summary := fmt.Sprintf("Total estimated monthly database cost: $%.2f across %d tenants.", totalMonthly, len(costs))

	writeJSON(w, map[string]interface{}{
		"costs":         entries,
		"total_monthly": totalMonthly,
		"summary":       summary,
	})
}

// handleAgentRecommendation returns suggested actions
func handleAgentRecommendation(w http.ResponseWriter, r *http.Request) {
	data := collector.GetData()
	activeAlerts := alertManager.GetActiveAlerts()

	// Calculate averages
	var totalAvgTime float64
	var totalQueryTime float64
	for _, t := range data.Tenants {
		totalAvgTime += t.AvgTimeMs
		totalQueryTime += t.AvgTimeMs * float64(t.Queries)
	}
	avgOfAvgs := 0.0
	if len(data.Tenants) > 0 {
		avgOfAvgs = totalAvgTime / float64(len(data.Tenants))
	}

	var recommendations []map[string]interface{}

	// Check for noisy tenants
	for _, t := range data.Tenants {
		if avgOfAvgs > 0 && t.AvgTimeMs > avgOfAvgs*5 {
			pct := 0.0
			tenantQT := t.AvgTimeMs * float64(t.Queries)
			if totalQueryTime > 0 {
				pct = tenantQT / totalQueryTime * 100
			}
			recommendations = append(recommendations, map[string]interface{}{
				"type":      "throttle",
				"tenant_id": t.TenantID,
				"severity":  "high",
				"summary":   fmt.Sprintf("Tenant %s avg query time is %.0fms (%.0fx above normal). Using %.1f%% of resources. Recommend throttling.", t.TenantID, t.AvgTimeMs, t.AvgTimeMs/avgOfAvgs, pct),
			})
		}
	}

	// Check cache hit ratio
	if data.Overview.CacheHitRatio > 0 && data.Overview.CacheHitRatio < 90 {
		recommendations = append(recommendations, map[string]interface{}{
			"type":     "performance",
			"severity": "medium",
			"summary":  fmt.Sprintf("Cache hit ratio is %.1f%% (below 90%%). Consider increasing shared_buffers or investigating query patterns.", data.Overview.CacheHitRatio),
		})
	}

	// Check connection pressure
	if data.Overview.MaxConnections > 0 {
		connPct := float64(data.Overview.TotalConnections) / float64(data.Overview.MaxConnections) * 100
		if connPct > 80 {
			recommendations = append(recommendations, map[string]interface{}{
				"type":     "connections",
				"severity": "high",
				"summary":  fmt.Sprintf("Connection usage at %.0f%% (%d/%d). Consider connection pooling or increasing max_connections.", connPct, data.Overview.TotalConnections, data.Overview.MaxConnections),
			})
		}
	}

	// Include active alerts as recommendations
	for _, a := range activeAlerts {
		recommendations = append(recommendations, map[string]interface{}{
			"type":      "alert",
			"tenant_id": a.TenantID,
			"severity":  string(a.Level),
			"summary":   a.Message,
		})
	}

	summary := fmt.Sprintf("%d recommendation(s) generated.", len(recommendations))
	if len(recommendations) == 0 {
		summary = "No recommendations. All systems operating within normal parameters."
	}

	writeJSON(w, map[string]interface{}{
		"recommendations": recommendations,
		"summary":         summary,
	})
}

func statusWord(healthy bool) string {
	if healthy {
		return "healthy"
	}
	return "degraded"
}
