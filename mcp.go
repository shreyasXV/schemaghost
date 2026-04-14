package main

import (
	"bufio"
	"encoding/json"
	"fmt"
	"io"
	"log"
	"os"
	"time"
)

// JSON-RPC 2.0 types for MCP protocol

type jsonRPCRequest struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      interface{}     `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

type jsonRPCResponse struct {
	JSONRPC string      `json:"jsonrpc"`
	ID      interface{} `json:"id"`
	Result  interface{} `json:"result,omitempty"`
	Error   *rpcError   `json:"error,omitempty"`
}

type rpcError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// MCP-specific types

type mcpServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

type mcpCapabilities struct {
	Tools map[string]interface{} `json:"tools"`
}

type mcpInitializeResult struct {
	ProtocolVersion string          `json:"protocolVersion"`
	Capabilities    mcpCapabilities `json:"capabilities"`
	ServerInfo      mcpServerInfo   `json:"serverInfo"`
}

type mcpTool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema interface{} `json:"inputSchema"`
}

type mcpToolsListResult struct {
	Tools []mcpTool `json:"tools"`
}

type mcpToolCallParams struct {
	Name      string                 `json:"name"`
	Arguments map[string]interface{} `json:"arguments"`
}

type mcpContent struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

type mcpToolCallResult struct {
	Content []mcpContent `json:"content"`
}

// mcpTools returns the list of tools exposed by the MCP server
func mcpTools() []mcpTool {
	return []mcpTool{
		{
			Name:        "list_tenants",
			Description: "Returns all tenants with current metrics (queries, avg_time, connections, cost)",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_tenant",
			Description: "Returns detailed metrics for one tenant",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"tenant_id": map[string]interface{}{
						"type":        "string",
						"description": "The tenant identifier",
					},
				},
				"required": []string{"tenant_id"},
			},
		},
		{
			Name:        "get_noisy_tenants",
			Description: "Returns tenants with avg query time above threshold",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"threshold_ms": map[string]interface{}{
						"type":        "number",
						"description": "Avg query time threshold in milliseconds (default: 100)",
					},
				},
			},
		},
		{
			Name:        "get_costs",
			Description: "Returns cost attribution for all tenants",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_tenant_cost",
			Description: "Returns cost attribution for a specific tenant",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"tenant_id": map[string]interface{}{
						"type":        "string",
						"description": "The tenant identifier",
					},
				},
				"required": []string{"tenant_id"},
			},
		},
		{
			Name:        "throttle_tenant",
			Description: "Manually throttle (cancel or terminate) a tenant's active queries",
			InputSchema: map[string]interface{}{
				"type": "object",
				"properties": map[string]interface{}{
					"tenant_id": map[string]interface{}{
						"type":        "string",
						"description": "The tenant identifier",
					},
					"action": map[string]interface{}{
						"type":        "string",
						"enum":        []string{"cancel", "terminate"},
						"description": "Action to take: cancel (pg_cancel_backend) or terminate (pg_terminate_backend)",
					},
				},
				"required": []string{"tenant_id", "action"},
			},
		},
		{
			Name:        "get_health",
			Description: "Returns overall database health (connections, cache hit ratio, QPS, active alerts)",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_throttle_events",
			Description: "Returns recent throttle events",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_anomalies",
			Description: "Returns active anomalies detected by statistical learning (z-score analysis of tenant metrics)",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
		{
			Name:        "get_predictions",
			Description: "Returns active predictions of when tenants will exceed thresholds based on trend analysis",
			InputSchema: map[string]interface{}{
				"type":       "object",
				"properties": map[string]interface{}{},
			},
		},
	}
}

// runMCP starts the MCP JSON-RPC server on stdin/stdout
func runMCP() {
	// Log to stderr so stdout stays clean for JSON-RPC
	log.SetOutput(os.Stderr)
	log.Println("MCP server starting...")

	reader := bufio.NewReader(os.Stdin)
	encoder := json.NewEncoder(os.Stdout)

	for {
		line, err := reader.ReadBytes('\n')
		if err != nil {
			if err == io.EOF {
				log.Println("MCP: stdin closed, exiting")
				return
			}
			log.Printf("MCP: read error: %v", err)
			return
		}

		var req jsonRPCRequest
		if err := json.Unmarshal(line, &req); err != nil {
			resp := jsonRPCResponse{
				JSONRPC: "2.0",
				ID:      nil,
				Error: &rpcError{
					Code:    -32700,
					Message: "Parse error",
					Data:    err.Error(),
				},
			}
			encoder.Encode(resp)
			continue
		}

		resp := handleMCPRequest(req)
		if err := encoder.Encode(resp); err != nil {
			log.Printf("MCP: write error: %v", err)
		}
	}
}

func handleMCPRequest(req jsonRPCRequest) jsonRPCResponse {
	switch req.Method {
	case "initialize":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result: mcpInitializeResult{
				ProtocolVersion: "2024-11-05",
				Capabilities:    mcpCapabilities{Tools: map[string]interface{}{}},
				ServerInfo:      mcpServerInfo{Name: "faultwall", Version: "1.0.0"},
			},
		}

	case "notifications/initialized":
		// Client acknowledgment — no response needed for notifications,
		// but since we read it as a request, just return empty if it has an ID
		if req.ID == nil {
			// Notifications don't get responses, but our loop expects one.
			// Return a minimal response that we won't encode (handled below).
			return jsonRPCResponse{JSONRPC: "2.0"}
		}
		return jsonRPCResponse{JSONRPC: "2.0", ID: req.ID, Result: map[string]interface{}{}}

	case "tools/list":
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Result:  mcpToolsListResult{Tools: mcpTools()},
		}

	case "tools/call":
		return handleMCPToolCall(req)

	default:
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error: &rpcError{
				Code:    -32601,
				Message: "Method not found",
				Data:    fmt.Sprintf("unknown method: %s", req.Method),
			},
		}
	}
}

func handleMCPToolCall(req jsonRPCRequest) jsonRPCResponse {
	var params mcpToolCallParams
	if err := json.Unmarshal(req.Params, &params); err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32602, Message: "Invalid params", Data: err.Error()},
		}
	}

	result, err := executeMCPTool(params.Name, params.Arguments)
	if err != nil {
		return jsonRPCResponse{
			JSONRPC: "2.0",
			ID:      req.ID,
			Error:   &rpcError{Code: -32000, Message: err.Error()},
		}
	}

	resultJSON, _ := json.Marshal(result)
	return jsonRPCResponse{
		JSONRPC: "2.0",
		ID:      req.ID,
		Result: mcpToolCallResult{
			Content: []mcpContent{{Type: "text", Text: string(resultJSON)}},
		},
	}
}

func executeMCPTool(name string, args map[string]interface{}) (interface{}, error) {
	switch name {
	case "list_tenants":
		return mcpListTenants()
	case "get_tenant":
		tid, _ := args["tenant_id"].(string)
		if tid == "" {
			return nil, fmt.Errorf("tenant_id is required")
		}
		return mcpGetTenant(tid)
	case "get_noisy_tenants":
		threshold := 100.0
		if v, ok := args["threshold_ms"].(float64); ok && v > 0 {
			threshold = v
		}
		return mcpGetNoisyTenants(threshold)
	case "get_costs":
		return mcpGetCosts()
	case "get_tenant_cost":
		tid, _ := args["tenant_id"].(string)
		if tid == "" {
			return nil, fmt.Errorf("tenant_id is required")
		}
		return mcpGetTenantCost(tid)
	case "throttle_tenant":
		tid, _ := args["tenant_id"].(string)
		action, _ := args["action"].(string)
		if tid == "" || action == "" {
			return nil, fmt.Errorf("tenant_id and action are required")
		}
		return mcpThrottleTenant(tid, action)
	case "get_health":
		return mcpGetHealth()
	case "get_throttle_events":
		return mcpGetThrottleEvents()
	case "get_anomalies":
		return mcpGetAnomalies()
	case "get_predictions":
		return mcpGetPredictions()
	default:
		return nil, fmt.Errorf("unknown tool: %s", name)
	}
}

func mcpListTenants() (interface{}, error) {
	if collector == nil || costEstimator == nil {
		return map[string]interface{}{"tenants": []interface{}{}, "message": "not available in proxy mode"}, nil
	}
	data := collector.GetData()
	costs := costEstimator.GetCosts()
	costMap := make(map[string]TenantCost)
	for _, c := range costs {
		costMap[c.TenantID] = c
	}

	type tenantInfo struct {
		TenantID    string  `json:"tenant_id"`
		Queries     int64   `json:"queries"`
		AvgTimeMs   float64 `json:"avg_time_ms"`
		Connections int     `json:"connections"`
		MonthlyCost float64 `json:"monthly_cost"`
	}

	var result []tenantInfo
	for _, t := range data.Tenants {
		info := tenantInfo{
			TenantID:    t.TenantID,
			Queries:     t.Queries,
			AvgTimeMs:   t.AvgTimeMs,
			Connections: t.Connections,
		}
		if c, ok := costMap[t.TenantID]; ok {
			info.MonthlyCost = c.MonthlyCost
		}
		result = append(result, info)
	}
	return result, nil
}

func mcpGetTenant(tenantID string) (interface{}, error) {
	data := collector.GetData()
	for _, t := range data.Tenants {
		if t.TenantID == tenantID {
			cost := costEstimator.GetTenantCost(tenantID)
			return map[string]interface{}{
				"metrics": t,
				"cost":    cost,
			}, nil
		}
	}
	return nil, fmt.Errorf("tenant %q not found", tenantID)
}

func mcpGetNoisyTenants(thresholdMs float64) (interface{}, error) {
	data := collector.GetData()
	var noisy []TenantMetrics
	for _, t := range data.Tenants {
		if t.AvgTimeMs > thresholdMs {
			noisy = append(noisy, t)
		}
	}
	return noisy, nil
}

func mcpGetCosts() (interface{}, error) {
	if costEstimator == nil {
		return []interface{}{}, nil
	}
	return costEstimator.GetCosts(), nil
}

func mcpGetTenantCost(tenantID string) (interface{}, error) {
	tc := costEstimator.GetTenantCost(tenantID)
	if tc == nil {
		return nil, fmt.Errorf("tenant %q not found", tenantID)
	}
	return tc, nil
}

func mcpThrottleTenant(tenantID, action string) (interface{}, error) {
	if action != "cancel" && action != "terminate" {
		return nil, fmt.Errorf("action must be 'cancel' or 'terminate'")
	}

	funcName := "pg_cancel_backend"
	if action == "terminate" {
		funcName = "pg_terminate_backend"
	}

	// Find active queries for this tenant
	rows, err := db.Query(`
		SELECT pid, COALESCE(query, ''),
		       EXTRACT(EPOCH FROM (now() - query_start)) * 1000 AS duration_ms
		FROM pg_stat_activity
		WHERE state = 'active'
		  AND pid != pg_backend_pid()
		  AND query_start IS NOT NULL
	`)
	if err != nil {
		return nil, fmt.Errorf("failed to query pg_stat_activity: %w", err)
	}
	defer rows.Close()

	var cancelled int
	for rows.Next() {
		var pid int
		var query string
		var durationMs float64
		if err := rows.Scan(&pid, &query, &durationMs); err != nil {
			continue
		}
		tid := extractTenantFromQuery(query, detector)
		if tid != tenantID {
			continue
		}

		var success bool
		err := db.QueryRow(fmt.Sprintf("SELECT %s($1)", funcName), pid).Scan(&success)
		if err == nil && success {
			cancelled++
			truncated := query
			if len(truncated) > 200 {
				truncated = truncated[:200] + "..."
			}
			event := ThrottleEvent{
				Timestamp:     time.Now(),
				TenantID:      tenantID,
				PID:           pid,
				QueryDuration: durationMs,
				Action:        "mcp_" + action,
				Query:         truncated,
			}
			throttler.addEvent(event)
		}
	}

	return map[string]interface{}{
		"tenant_id":        tenantID,
		"action":           action,
		"queries_affected": cancelled,
	}, nil
}

func mcpGetHealth() (interface{}, error) {
	data := collector.GetData()
	activeAlerts := alertManager.GetActiveAlerts()

	return map[string]interface{}{
		"connections":     data.Overview.TotalConnections,
		"max_connections": data.Overview.MaxConnections,
		"cache_hit_ratio": data.Overview.CacheHitRatio,
		"qps":             data.Overview.QueriesPerSec,
		"db_size":         data.Overview.DBSize,
		"active_alerts":   len(activeAlerts),
		"total_tenants":   len(data.Tenants),
		"collected_at":    data.Overview.CollectedAt,
	}, nil
}

func mcpGetThrottleEvents() (interface{}, error) {
	if throttler == nil {
		return []interface{}{}, nil
	}
	return throttler.GetEvents(), nil
}

func mcpGetAnomalies() (interface{}, error) {
	if anomalyDetector == nil {
		return map[string]interface{}{"active_count": 0, "anomalies": []interface{}{}}, nil
	}
	active := anomalyDetector.GetActive()
	var summaries []map[string]interface{}
	for _, a := range active {
		summaries = append(summaries, map[string]interface{}{
			"tenant_id": a.TenantID,
			"metric":    a.Metric,
			"severity":  a.Severity,
			"z_score":   a.ZScore,
			"summary":   a.Message,
		})
	}
	return map[string]interface{}{
		"active_count": len(active),
		"anomalies":    summaries,
	}, nil
}

func mcpGetPredictions() (interface{}, error) {
	if predictor == nil {
		return map[string]interface{}{"predictions": []interface{}{}}, nil
	}
	preds := predictor.GetPredictions()
	var summaries []map[string]interface{}
	for _, p := range preds {
		summaries = append(summaries, map[string]interface{}{
			"tenant_id":         p.TenantID,
			"metric":            p.Metric,
			"time_to_threshold": p.TimeToThresholdMin,
			"trend":             p.Trend,
			"confidence":        p.Confidence,
			"summary":           p.Message,
		})
	}
	return map[string]interface{}{
		"prediction_count": len(preds),
		"predictions":      summaries,
	}, nil
}
