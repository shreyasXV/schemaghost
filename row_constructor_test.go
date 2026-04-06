package main

import (
	"fmt"
	"strings"
	"testing"
)

func TestRowConstructorBypass(t *testing.T) {
	tests := []struct {
		name  string
		query string
		want  string
	}{
		{
			"ROW constructor with blocked email subquery",
			"SELECT f.id, pg_catalog.int4send(pg_catalog.hashtext(ROW(f.id, f.message, f.rating, (SELECT u.email FROM public.users u LIMIT 1))::text)) FROM public.feedback f",
			"users",
		},
		{
			"ROW constructor with password_hash subquery",
			"SELECT f.id, md5(ROW(f.id, (SELECT u.password_hash FROM public.users u LIMIT 1))::text) FROM public.feedback f",
			"users",
		},
		{
			"ROW constructor with payments subquery",
			"SELECT f.id, substr(ROW(f.id, f.message, (SELECT p.amount FROM public.payments p LIMIT 1))::text, 1, 50) FROM public.feedback f",
			"payments",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pq := ParseQuery(tt.query)
			if !pq.UsedAST {
				t.Fatalf("AST parse failed")
			}
			found := false
			for _, tbl := range pq.Tables {
				if strings.Contains(tbl, tt.want) {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected table %q in extracted tables %v\nQuery: %s", tt.want, pq.Tables, tt.query)
			} else {
				t.Logf("OK: found %q in %v", tt.want, pq.Tables)
			}
		})
	}
}

func TestRowConstructorPolicyBlock(t *testing.T) {
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

	queries := []string{
		"SELECT f.id, pg_catalog.int4send(pg_catalog.hashtext(ROW(f.id, f.message, f.rating, (SELECT u.email FROM public.users u LIMIT 1))::text)) FROM public.feedback f",
		"SELECT f.id, md5(ROW(f.id, (SELECT u.password_hash FROM public.users u LIMIT 1))::text) FROM public.feedback f",
		"SELECT f.id, substr(ROW((SELECT string_agg(u.email, ',') FROM public.users u), f.rating)::text, 1, 100) FROM public.feedback f",
	}

	for i, q := range queries {
		v := pe.CheckQuery(identity, q, 0)
		if v == nil {
			t.Errorf("Query %d BYPASSED policy: %s", i, q[:120])
		} else {
			t.Logf("Query %d blocked: reason=%s", i, v.Reason)
		}
	}
}

func TestRowConstructorTableExtraction(t *testing.T) {
	// Verify the parser extracts tables from ROW() args
	q := "SELECT ROW(1, (SELECT email FROM public.users LIMIT 1), (SELECT amount FROM public.payments LIMIT 1))"
	pq := ParseQuery(q)
	if !pq.UsedAST {
		t.Fatal("AST parse failed")
	}
	
	foundUsers := false
	foundPayments := false
	for _, tbl := range pq.Tables {
		if strings.Contains(tbl, "users") { foundUsers = true }
		if strings.Contains(tbl, "payments") { foundPayments = true }
	}
	
	fmt.Printf("Extracted tables: %v\n", pq.Tables)
	if !foundUsers {
		t.Error("Missing 'users' table from ROW() subquery")
	}
	if !foundPayments {
		t.Error("Missing 'payments' table from ROW() subquery")
	}
}
