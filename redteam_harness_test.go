package main

import (
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"testing"
)

// RedTeamResult holds the result of checking a single attack query
type RedTeamResult struct {
	Query     string   `json:"query"`
	Blocked   bool     `json:"blocked"`
	Reason    string   `json:"reason"`
	Operation string   `json:"operation"`
	AllOps    []string `json:"all_ops"`
	Tables    []string `json:"tables"`
	Functions []string `json:"functions"`
	UsedAST   bool     `json:"used_ast"`
}

// TestRedTeamHarness reads attack queries from REDTEAM_QUERIES env var (JSON array),
// runs each through ParseQuery + CheckQuery, and writes results to REDTEAM_OUTPUT file.
func TestRedTeamHarness(t *testing.T) {
	queriesJSON := os.Getenv("REDTEAM_QUERIES")
	outputFile := os.Getenv("REDTEAM_OUTPUT")
	if queriesJSON == "" || outputFile == "" {
		t.Skip("REDTEAM_QUERIES and REDTEAM_OUTPUT must be set")
	}

	var queries []string
	if err := json.Unmarshal([]byte(queriesJSON), &queries); err != nil {
		// Try reading from file if it's a path
		data, ferr := os.ReadFile(queriesJSON)
		if ferr != nil {
			t.Fatalf("Failed to parse queries: %v", err)
		}
		if err2 := json.Unmarshal(data, &queries); err2 != nil {
			t.Fatalf("Failed to parse queries from file: %v", err2)
		}
	}

	// Load policy engine with enforce mode
	os.Setenv("POLICY_ENFORCEMENT", "enforce")
	pe := NewPolicyEngine()

	// Test as cursor-ai agent on summarize-feedback mission
	identity := &AgentIdentity{
		AgentID:   "cursor-ai",
		MissionID: "summarize-feedback",
	}

	var results []RedTeamResult
	bypasses := 0

	for _, query := range queries {
		parsed := ParseQuery(query)
		violation := pe.CheckQuery(identity, query, 12345)

		result := RedTeamResult{
			Query:     query,
			Blocked:   violation != nil,
			Operation: parsed.Operation,
			AllOps:    parsed.Operations,
			Tables:    parsed.Tables,
			Functions: parsed.Functions,
			UsedAST:   parsed.UsedAST,
		}
		if violation != nil {
			result.Reason = violation.Reason
		} else {
			result.Reason = "BYPASSED"
			bypasses++
		}

		results = append(results, result)
	}

	// Write results
	out, _ := json.MarshalIndent(results, "", "  ")
	os.WriteFile(outputFile, out, 0644)

	// Also write summary
	summary := fmt.Sprintf("Total: %d, Blocked: %d, Bypassed: %d (%.1f%%)\n",
		len(queries), len(queries)-bypasses, bypasses, float64(bypasses)/float64(len(queries))*100)

	// Print bypasses for easy viewing
	fmt.Println("\n=== RED TEAM RESULTS ===")
	fmt.Print(summary)
	if bypasses > 0 {
		fmt.Println("\n--- BYPASSES ---")
		for _, r := range results {
			if !r.Blocked {
				fmt.Printf("  BYPASS: op=%s tables=%v funcs=%v ast=%v\n    SQL: %s\n",
					r.Operation, r.Tables, r.Functions, r.UsedAST, truncateForDisplay(r.Query))
			}
		}
	}

	// Write bypasses to separate file for the agent to learn from
	var bypassQueries []RedTeamResult
	for _, r := range results {
		if !r.Blocked {
			bypassQueries = append(bypassQueries, r)
		}
	}
	bypassOut, _ := json.MarshalIndent(bypassQueries, "", "  ")
	bypassFile := strings.TrimSuffix(outputFile, ".json") + "_bypasses.json"
	os.WriteFile(bypassFile, bypassOut, 0644)
}

func truncateForDisplay(s string) string {
	if len(s) > 150 {
		return s[:150] + "..."
	}
	return s
}
