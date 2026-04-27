package main

import "testing"

// Regression tests for docs/compatibility.md bug #2:
// schema-unqualified table references must not bypass blocked_tables.
//
// Before the fix: isTableBlocked("users", []{"public.users"}) returned false
// because Postgres search_path resolves "users" → "public.users" transparently,
// but the extractor returned "users" and the matcher did exact-string compare only.
// That let any agent evade blocked_tables by omitting the schema prefix.
func TestIsTableBlocked_SchemaAgnostic(t *testing.T) {
	cases := []struct {
		name    string
		table   string
		list    []string
		want    bool
	}{
		// Exact matches (regression check — must still work)
		{"exact qualified", "public.users", []string{"public.users"}, true},
		{"exact bare", "users", []string{"users"}, true},
		{"exact not present", "feedback", []string{"public.users"}, false},

		// Wildcard (regression check)
		{"wildcard match", "pg_catalog.pg_user", []string{"pg_catalog.*"}, true},
		{"wildcard miss", "public.users", []string{"pg_catalog.*"}, false},

		// Bug #2 fix: bare query name against qualified blocklist entry
		{"bare→qualified: FROM users vs block public.users", "users", []string{"public.users"}, true},
		{"bare→qualified: FROM payments vs block public.payments", "payments", []string{"public.payments", "public.users"}, true},
		{"bare→qualified: FROM products unrelated", "products", []string{"public.users"}, false},

		// Reverse: qualified query against bare blocklist entry
		{"qualified→bare: FROM public.users vs block users", "public.users", []string{"users"}, true},
		{"qualified→bare: FROM app.users vs block users (search_path bypass attempt)", "app.users", []string{"users"}, true},

		// Cross-schema same leaf — this is intentional: the whole point is that
		// Postgres search_path can resolve "users" to any schema, so if the
		// operator has blocked "users" without a schema, every schema's "users"
		// should be blocked.
		{"cross-schema leaf match is intentional", "secret.users", []string{"public.users"}, true},

		// Case insensitivity (regression)
		{"case insensitive qualified", "PUBLIC.USERS", []string{"public.users"}, true},
		{"case insensitive bare", "Users", []string{"public.users"}, true},

		// Empty list / empty input
		{"empty list", "users", []string{}, false},
		{"empty table", "", []string{"public.users"}, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := isTableBlocked(tc.table, tc.list)
			if got != tc.want {
				t.Errorf("isTableBlocked(%q, %v) = %v, want %v", tc.table, tc.list, got, tc.want)
			}
		})
	}
}

// End-to-end: CheckQuery must block bare-table SELECTs when blocked_tables
// contains the schema-qualified form. This is the exact attack that bypassed
// FaultWall in the April 2026 compatibility audit.
func TestCheckQuery_BareTableBlocked(t *testing.T) {
	pe := &PolicyEngine{
		config: &PolicyConfig{
			DefaultPolicy: "allow",
			Agents: map[string]AgentPolicy{
				"testagent": {
					AuthToken:     "tok",
					Profile:       "standard",
					BlockedTables: []string{"public.users", "public.payments"},
				},
			},
			Unidentified: UnidentifiedPolicy{Policy: "allow"},
		},
		enforcement: "enforce",
	}
	identity := &AgentIdentity{AgentID: "testagent", MissionID: "attack", Token: "tok"}

	// Bug #2: these used to bypass
	bareAttacks := []string{
		"SELECT COUNT(*) FROM users",
		"SELECT * FROM users WHERE id = 1",
		"SELECT COUNT(*) FROM payments",
	}
	for _, q := range bareAttacks {
		v := pe.CheckQuery(identity, q, 0)
		if v == nil {
			t.Errorf("expected block for bare-table attack %q, got nil", q)
		} else if v.Reason != "blocked_table" {
			t.Errorf("expected reason=blocked_table for %q, got %q", q, v.Reason)
		}
	}

	// Qualified form should still block (regression)
	if v := pe.CheckQuery(identity, "SELECT * FROM public.users", 0); v == nil {
		t.Error("expected block for qualified FROM public.users")
	}

	// Unrelated tables should pass
	if v := pe.CheckQuery(identity, "SELECT COUNT(*) FROM feedback", 0); v != nil && v.Reason == "blocked_table" {
		t.Errorf("expected pass for unrelated table, got blocked_table: %+v", v)
	}
}
