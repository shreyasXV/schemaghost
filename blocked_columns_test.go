package main

import (
	"strings"
	"testing"
)

// ── BlockedColumns (column-level denylist) ──────────────────────────────────
//
// Column-level enforcement: a policy may specify per-table column denylists.
// A query that references a blocked column on a listed table is denied with
// reason "blocked_column:<table>.<col>". Legitimate queries on the same table
// that touch only allowed columns must pass through.

func blockedColsEngine() *PolicyEngine {
	return newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"support-agent": {
				Profile: "standard",
				Missions: map[string]MissionPolicy{
					"respond-to-ticket": {
						Tables: []string{"public.users", "public.feedback"},
					},
				},
				BlockedColumns: map[string][]string{
					"users": {"ssn", "password_hash", "api_key"},
				},
			},
		},
	})
}

func TestBlockedColumnsDirectSelect(t *testing.T) {
	pe := blockedColsEngine()

	// ssn is blocked — must deny
	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT full_name, email, ssn FROM public.users LIMIT 5", 1)
	if v == nil {
		t.Fatal("expected violation for ssn column read, got nil")
	}
	if !strings.HasPrefix(v.Reason, "blocked_column:") {
		t.Errorf("expected blocked_column reason, got %q", v.Reason)
	}
	if !strings.Contains(v.Reason, "ssn") {
		t.Errorf("expected ssn in reason, got %q", v.Reason)
	}
}

func TestBlockedColumnsAllowedColumnsPass(t *testing.T) {
	pe := blockedColsEngine()

	// Only name and email — must pass
	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT full_name, email FROM public.users LIMIT 5", 1)
	if v != nil {
		t.Errorf("allowed columns should pass, got violation: %s", v.Reason)
	}
}

func TestBlockedColumnsQualifiedReference(t *testing.T) {
	pe := blockedColsEngine()

	// users.ssn (qualified) — must deny
	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT u.full_name, u.ssn FROM public.users u", 1)
	if v == nil {
		t.Fatal("expected violation for qualified ssn column read, got nil")
	}
	if !strings.HasPrefix(v.Reason, "blocked_column:") {
		t.Errorf("expected blocked_column reason, got %q", v.Reason)
	}
}

func TestBlockedColumnsPasswordHash(t *testing.T) {
	pe := blockedColsEngine()

	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT email, password_hash FROM public.users", 1)
	if v == nil {
		t.Fatal("expected violation for password_hash column read, got nil")
	}
	if !strings.Contains(v.Reason, "password_hash") {
		t.Errorf("expected password_hash in reason, got %q", v.Reason)
	}
}

func TestBlockedColumnsApiKey(t *testing.T) {
	pe := blockedColsEngine()

	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT email, api_key FROM public.users", 1)
	if v == nil {
		t.Fatal("expected violation for api_key column read, got nil")
	}
	if !strings.Contains(v.Reason, "api_key") {
		t.Errorf("expected api_key in reason, got %q", v.Reason)
	}
}

func TestBlockedColumnsInWhereClause(t *testing.T) {
	pe := blockedColsEngine()

	// ssn appears only in WHERE — still a column reference, still must deny.
	// A support agent filtering by SSN is reading that column even if not in SELECT.
	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT email FROM public.users WHERE ssn = '123-45-6789'", 1)
	if v == nil {
		t.Fatal("expected violation for ssn in WHERE, got nil")
	}
	if !strings.Contains(v.Reason, "ssn") {
		t.Errorf("expected ssn in reason, got %q", v.Reason)
	}
}

func TestBlockedColumnsStarDoesNotAutoBlock(t *testing.T) {
	// SELECT * alone does not name columns — the column-block check does not
	// fire on star by itself (parser records no column names for A_Star).
	// The correct defense for SELECT * on a PII table is `blocked_tables`.
	// This test documents that behavior so callers don't assume otherwise.
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"support-agent": {
				Profile: "standard",
				Missions: map[string]MissionPolicy{
					"respond-to-ticket": {
						Tables: []string{"public.users"},
					},
				},
				BlockedColumns: map[string][]string{
					"users": {"ssn"},
				},
			},
		},
	})

	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT * FROM public.users", 1)
	// No column-level violation expected; star expands server-side.
	// Callers should pair BlockedColumns with BlockedTables or deny-star logic.
	if v != nil && strings.HasPrefix(v.Reason, "blocked_column:") {
		t.Errorf("SELECT * should not trigger column-level block directly, got %q", v.Reason)
	}
}

func TestBlockedColumnsOtherTableNotAffected(t *testing.T) {
	pe := blockedColsEngine()

	// feedback table has no blocked columns — ssn-as-column-name is only
	// blocked on the users table.
	v := pe.CheckQuery(id("support-agent", "respond-to-ticket"),
		"SELECT id, comment FROM public.feedback LIMIT 5", 1)
	if v != nil {
		t.Errorf("feedback query should pass, got violation: %s", v.Reason)
	}
}

func TestBlockedColumnsUpdateSet(t *testing.T) {
	// UPDATE ... SET ssn = 'x' must also be denied. The agent is writing
	// to the blocked column, not just reading.
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"support-agent": {
				Profile: "standard",
				Missions: map[string]MissionPolicy{
					"update-ticket": {
						Tables: []string{"public.users: [UPDATE]"},
					},
				},
				BlockedColumns: map[string][]string{
					"users": {"ssn"},
				},
			},
		},
	})

	v := pe.CheckQuery(id("support-agent", "update-ticket"),
		"UPDATE public.users SET ssn = '999-99-9999' WHERE id = 1", 1)
	if v == nil {
		t.Fatal("expected violation for UPDATE SET ssn, got nil")
	}
}

func TestBlockedColumnsConfigKeyWithSchema(t *testing.T) {
	// blocked_columns key can be "public.users" or bare "users" — both must
	// match when the query uses either form.
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"support-agent": {
				Profile: "standard",
				Missions: map[string]MissionPolicy{
					"read": {
						Tables: []string{"public.users"},
					},
				},
				BlockedColumns: map[string][]string{
					"public.users": {"ssn"},
				},
			},
		},
	})

	v := pe.CheckQuery(id("support-agent", "read"),
		"SELECT ssn FROM users", 1)
	if v == nil {
		t.Fatal("expected violation when config uses public.users and query uses users, got nil")
	}
	if !strings.Contains(v.Reason, "ssn") {
		t.Errorf("expected ssn in reason, got %q", v.Reason)
	}
}
