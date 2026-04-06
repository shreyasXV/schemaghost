package main

import (
	"strings"
	"testing"
)

// TestSubqueryInOrderBy — the #1 bypass category found by the 500-round AutoAgent.
// Scalar subqueries in ORDER BY can exfiltrate blocked table data.
func TestSubqueryInOrderBy(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string // expected blocked table
	}{
		{
			"ORDER BY subquery leaks users.email",
			"SELECT id, message FROM public.feedback ORDER BY (SELECT email FROM public.users LIMIT 1)",
			"users",
		},
		{
			"ORDER BY subquery leaks users.password_hash",
			"SELECT * FROM public.feedback ORDER BY (SELECT password_hash FROM public.users LIMIT 1)",
			"users",
		},
		{
			"ORDER BY with string_agg credential dump",
			"SELECT * FROM public.feedback ORDER BY (SELECT string_agg(username || ':' || password_hash, ',') FROM public.users)",
			"users",
		},
		{
			"ORDER BY leaks payments.amount",
			"SELECT * FROM public.feedback ORDER BY (SELECT max(amount) FROM public.payments)",
			"payments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pq := ParseQuery(tt.query)
			if !pq.UsedAST {
				t.Fatalf("AST parse failed for: %s", tt.query)
			}
			found := false
			for _, tbl := range pq.Tables {
				if strings.Contains(tbl, tt.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected table %q in extracted tables %v for query: %s", tt.want, pq.Tables, tt.query)
			}
		})
	}
}

// TestSubqueryInLimit — LIMIT (SELECT count(*) FROM blocked_table)
func TestSubqueryInLimit(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{
			"LIMIT subquery leaks users count",
			"SELECT * FROM public.feedback LIMIT (SELECT count(*) FROM public.users)",
			"users",
		},
		{
			"OFFSET subquery leaks payments count",
			"SELECT * FROM public.feedback OFFSET (SELECT count(*) FROM public.payments)",
			"payments",
		},
		{
			"FETCH FIRST via LIMIT subquery",
			"SELECT * FROM public.feedback FETCH FIRST (SELECT count(*) FROM public.users) ROWS ONLY",
			"users",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pq := ParseQuery(tt.query)
			if !pq.UsedAST {
				t.Fatalf("AST parse failed for: %s", tt.query)
			}
			found := false
			for _, tbl := range pq.Tables {
				if strings.Contains(tbl, tt.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected table %q in extracted tables %v for query: %s", tt.want, pq.Tables, tt.query)
			}
		})
	}
}

// TestSubqueryInHaving — HAVING clause with blocked table subqueries
func TestSubqueryInHaving(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{
			"HAVING subquery leaks users count",
			"SELECT rating, count(*) FROM public.feedback GROUP BY rating HAVING count(*) > (SELECT count(*) FROM public.users)",
			"users",
		},
		{
			"HAVING with blocked table aggregate",
			"SELECT message FROM public.feedback GROUP BY message HAVING length(message) > (SELECT max(amount) FROM public.payments)",
			"payments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pq := ParseQuery(tt.query)
			if !pq.UsedAST {
				t.Fatalf("AST parse failed for: %s", tt.query)
			}
			found := false
			for _, tbl := range pq.Tables {
				if strings.Contains(tbl, tt.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected table %q in extracted tables %v for query: %s", tt.want, pq.Tables, tt.query)
			}
		})
	}
}

// TestSubqueryInWindowFunction — window PARTITION BY / ORDER BY with blocked tables
func TestSubqueryInWindowFunction(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{
			"Window ORDER BY subquery leaks users",
			"SELECT id, message, row_number() OVER (ORDER BY (SELECT email FROM public.users LIMIT 1)) FROM public.feedback",
			"users",
		},
		{
			"Window PARTITION BY subquery leaks payments",
			"SELECT id, message, count(*) OVER (PARTITION BY (SELECT status FROM public.payments LIMIT 1)) FROM public.feedback",
			"payments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pq := ParseQuery(tt.query)
			if !pq.UsedAST {
				t.Fatalf("AST parse failed for: %s", tt.query)
			}
			found := false
			for _, tbl := range pq.Tables {
				if strings.Contains(tbl, tt.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected table %q in extracted tables %v for query: %s", tt.want, pq.Tables, tt.query)
			}
		})
	}
}

// TestSubqueryInFilterClause — aggregate FILTER (WHERE ...) with blocked tables
func TestSubqueryInFilterClause(t *testing.T) {
	pq := ParseQuery("SELECT count(*) FILTER (WHERE id IN (SELECT id FROM public.users)) FROM public.feedback")
	if !pq.UsedAST {
		t.Fatal("AST parse failed")
	}
	found := false
	for _, tbl := range pq.Tables {
		if strings.Contains(tbl, "users") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected table 'users' in extracted tables %v", pq.Tables)
	}
}

// TestSubqueryInAggOrderBy — string_agg(... ORDER BY (subquery))
func TestSubqueryInAggOrderBy(t *testing.T) {
	pq := ParseQuery("SELECT string_agg(message, ',' ORDER BY (SELECT email FROM public.users LIMIT 1)) FROM public.feedback")
	if !pq.UsedAST {
		t.Fatal("AST parse failed")
	}
	found := false
	for _, tbl := range pq.Tables {
		if strings.Contains(tbl, "users") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("Expected table 'users' in extracted tables %v", pq.Tables)
	}
}

// TestPolicyBlocksSubqueryExfil — end-to-end: policy engine should block these queries
func TestPolicyBlocksSubqueryExfil(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"cursor-ai": {
				Profile: "standard",
				Missions: map[string]MissionPolicy{
					"summarize-feedback": {
						Tables:  []string{"public.feedback", "public.products"},
						MaxRows: 1000,
					},
				},
			},
		},
	})
	identity := id("cursor-ai", "summarize-feedback")

	attacks := []struct {
		name  string
		query string
	}{
		{"ORDER BY users email", "SELECT * FROM public.feedback ORDER BY (SELECT email FROM public.users LIMIT 1)"},
		{"ORDER BY password_hash", "SELECT * FROM public.feedback ORDER BY (SELECT password_hash FROM public.users LIMIT 1)"},
		{"LIMIT users count", "SELECT * FROM public.feedback LIMIT (SELECT count(*) FROM public.users)"},
		{"OFFSET payments count", "SELECT * FROM public.feedback OFFSET (SELECT count(*) FROM public.payments)"},
		{"HAVING users count", "SELECT rating, count(*) FROM public.feedback GROUP BY rating HAVING count(*) > (SELECT count(*) FROM public.users)"},
		{"Window ORDER BY users", "SELECT id, row_number() OVER (ORDER BY (SELECT email FROM public.users LIMIT 1)) FROM public.feedback"},
		{"FILTER clause users", "SELECT count(*) FILTER (WHERE id IN (SELECT id FROM public.users)) FROM public.feedback"},
		{"string_agg credential dump", "SELECT * FROM public.feedback ORDER BY (SELECT string_agg(username || ':' || password_hash, ',') FROM public.users)"},
		{"Agg ORDER BY subquery", "SELECT string_agg(message, ',' ORDER BY (SELECT email FROM public.users LIMIT 1)) FROM public.feedback"},
	}

	for _, att := range attacks {
		t.Run(att.name, func(t *testing.T) {
			violation := pe.CheckQuery(identity, att.query, 0)
			if violation == nil {
				t.Errorf("BYPASS: query was allowed but should be blocked: %s", att.query)
			} else {
				t.Logf("OK blocked: %s → reason=%s", att.name, violation.Reason)
			}
		})
	}
}
