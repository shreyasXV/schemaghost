package main

import (
	"testing"
)

func newTestEngine(cfg *PolicyConfig) *PolicyEngine {
	return &PolicyEngine{
		config:      cfg,
		enforcement: "enforce",
	}
}

func id(agent, mission string) *AgentIdentity {
	return &AgentIdentity{AgentID: agent, MissionID: mission}
}

// ── Profile: permissive ──

func TestProfilePermissive(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "permissive"},
		},
	})

	// Permissive allows everything
	for _, op := range []string{
		"SELECT 1",
		"DROP TABLE t",
		"ALTER SYSTEM SET work_mem = '256MB'",
		"CREATE EXTENSION pgcrypto",
		"DO $$ BEGIN END $$",
		"GRANT SELECT ON t TO role1",
		"VACUUM t",
	} {
		v := pe.CheckQuery(id("agent1", ""), op, 1)
		if v != nil {
			t.Errorf("permissive should allow %q, got violation: %s", op, v.Reason)
		}
	}
}

func TestProfilePermissiveAllowsUnknown(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "permissive"},
		},
	})

	// UNKNOWN via garbage SQL — permissive allows it
	v := pe.CheckQuery(id("agent1", ""), "THIS IS NOT VALID SQL AT ALL !!!", 1)
	if v != nil {
		t.Errorf("permissive should allow UNKNOWN, got violation: %s", v.Reason)
	}
}

// ── Profile: standard ──

func TestProfileStandard(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	// Standard allows DML (except COPY), EXPLAIN, SESSION, TRANSACTION
	allowed := []string{
		"SELECT 1",
		"INSERT INTO t(a) VALUES(1)",
		"UPDATE t SET a=1 WHERE id=1",
		"DELETE FROM t WHERE id=1",
		"EXPLAIN SELECT 1",
		"BEGIN",
		"SET work_mem = '256MB'",
		"SHOW work_mem",
		"PREPARE stmt AS SELECT 1",
	}
	for _, q := range allowed {
		v := pe.CheckQuery(id("agent1", ""), q, 1)
		if v != nil {
			t.Errorf("standard should allow %q, got violation: %s", q, v.Reason)
		}
	}

	// Standard blocks DCL, ADMIN, EXTENSION, FUNCTION categories + COPY
	blocked := []struct {
		query string
		desc  string
	}{
		{"COPY t FROM STDIN", "COPY (blocked op)"},
		{"GRANT SELECT ON t TO role1", "DCL"},
		{"CREATE ROLE readonly LOGIN", "DCL"},
		{"ALTER ROLE admin SUPERUSER", "DCL"},
		{"VACUUM t", "ADMIN"},
		{"ALTER SYSTEM SET work_mem = '256MB'", "ADMIN"},
		{"CHECKPOINT", "ADMIN"},
		{"CREATE EXTENSION pgcrypto", "EXTENSION"},
		{"DO $$ BEGIN END $$", "FUNCTION"},
		{"CREATE FUNCTION f() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql", "FUNCTION"},
	}
	for _, tt := range blocked {
		v := pe.CheckQuery(id("agent1", ""), tt.query, 1)
		if v == nil {
			t.Errorf("standard should block %s (%q)", tt.desc, tt.query)
		}
	}
}

func TestProfileStandardBlocksUnknown(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "THIS IS NOT VALID SQL AT ALL !!!", 1)
	if v == nil {
		t.Error("standard should block UNKNOWN operations")
	}
}

func TestProfileStandardConditions(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	// DELETE without WHERE should be blocked by condition
	v := pe.CheckQuery(id("agent1", ""), "DELETE FROM t", 1)
	if v == nil {
		t.Error("standard should block DELETE without WHERE")
	} else if v.Reason != "condition_violated" {
		t.Errorf("expected condition_violated, got %s", v.Reason)
	}

	// UPDATE without WHERE should be blocked by condition
	v = pe.CheckQuery(id("agent1", ""), "UPDATE t SET a=1", 1)
	if v == nil {
		t.Error("standard should block UPDATE without WHERE")
	} else if v.Reason != "condition_violated" {
		t.Errorf("expected condition_violated, got %s", v.Reason)
	}

	// DELETE with WHERE should pass
	v = pe.CheckQuery(id("agent1", ""), "DELETE FROM t WHERE id=1", 1)
	if v != nil {
		t.Errorf("standard should allow DELETE with WHERE, got %s", v.Reason)
	}
}

// ── Profile: strict ──

func TestProfileStrict(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "strict"},
		},
	})

	// Strict allows only SELECT, INSERT, UPDATE, DELETE, EXPLAIN, TRANSACTION
	allowed := []string{
		"SELECT 1",
		"INSERT INTO t(a) VALUES(1)",
		"UPDATE t SET a=1 WHERE id=1",
		"DELETE FROM t WHERE id=1",
		"EXPLAIN SELECT 1",
		"BEGIN",
	}
	for _, q := range allowed {
		v := pe.CheckQuery(id("agent1", ""), q, 1)
		if v != nil {
			t.Errorf("strict should allow %q, got violation: %s", q, v.Reason)
		}
	}

	// Everything else blocked
	blocked := []string{
		"CREATE TABLE t(id int)",
		"DROP TABLE t",
		"GRANT SELECT ON t TO role1",
		"VACUUM t",
		"CREATE EXTENSION pgcrypto",
		"DO $$ BEGIN END $$",
		"COPY t FROM STDIN",
		"SET work_mem = '256MB'",
		"LOCK TABLE t IN ACCESS EXCLUSIVE MODE",
	}
	for _, q := range blocked {
		v := pe.CheckQuery(id("agent1", ""), q, 1)
		if v == nil {
			t.Errorf("strict should block %q", q)
		}
	}
}

func TestProfileStrictBlocksUnknown(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "strict"},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "THIS IS NOT VALID SQL AT ALL !!!", 1)
	if v == nil {
		t.Error("strict should block UNKNOWN operations")
	}
}

// ── Profile overrides ──

func TestProfileOverrideAllow(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				Profile: "standard",
				ProfileOverrides: &ProfileOverrides{
					Allow: []string{"COPY"}, // allow COPY even though standard blocks it
				},
			},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "COPY t FROM STDIN", 1)
	if v != nil {
		t.Errorf("override should allow COPY, got violation: %s", v.Reason)
	}
}

func TestProfileOverrideBlock(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				Profile: "standard",
				ProfileOverrides: &ProfileOverrides{
					Block: []string{"DELETE"}, // block DELETE even though standard allows it
				},
			},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "DELETE FROM t WHERE id=1", 1)
	if v == nil {
		t.Error("override should block DELETE")
	}
}

func TestProfileOverrideBlockTakesPrecedence(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				Profile: "standard",
				ProfileOverrides: &ProfileOverrides{
					Allow: []string{"SELECT"},
					Block: []string{"SELECT"}, // block wins over allow
				},
			},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "SELECT 1", 1)
	if v == nil {
		t.Error("block override should take precedence over allow")
	}
}

// ── Backward compatibility ──

func TestLegacyBlockedOperations(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				BlockedOperations: []string{"DROP", "TRUNCATE", "DELETE"},
			},
		},
	})

	// Blocked operations
	v := pe.CheckQuery(id("agent1", ""), "DROP TABLE t", 1)
	if v == nil {
		t.Error("legacy should block DROP")
	}

	v = pe.CheckQuery(id("agent1", ""), "TRUNCATE t", 1)
	if v == nil {
		t.Error("legacy should block TRUNCATE")
	}

	// Allowed operations
	v = pe.CheckQuery(id("agent1", ""), "SELECT 1", 1)
	if v != nil {
		t.Errorf("legacy should allow SELECT, got %s", v.Reason)
	}

	v = pe.CheckQuery(id("agent1", ""), "INSERT INTO t(a) VALUES(1)", 1)
	if v != nil {
		t.Errorf("legacy should allow INSERT, got %s", v.Reason)
	}
}

func TestLegacyBlocksUnknown(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				BlockedOperations: []string{"DROP"},
			},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "THIS IS NOT VALID SQL AT ALL !!!", 1)
	if v == nil {
		t.Error("legacy (no profile) should block UNKNOWN")
	}
}

func TestProfileWinsOverBlockedOperations(t *testing.T) {
	// If both profile and blocked_operations exist, profile takes precedence
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				Profile:           "permissive",
				BlockedOperations: []string{"SELECT"}, // should be ignored
			},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "SELECT 1", 1)
	if v != nil {
		t.Error("profile should win over blocked_operations — SELECT should be allowed")
	}
}

// ── Custom profiles ──

func TestCustomProfileExtendsStrict(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Profiles: map[string]CustomProfileConfig{
			"custom-readonly": {
				Extends:           "strict",
				AllowedOperations: []string{"SELECT", "EXPLAIN"},
			},
		},
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "custom-readonly"},
		},
	})

	// Only SELECT and EXPLAIN allowed
	v := pe.CheckQuery(id("agent1", ""), "SELECT 1", 1)
	if v != nil {
		t.Errorf("custom-readonly should allow SELECT, got %s", v.Reason)
	}

	v = pe.CheckQuery(id("agent1", ""), "EXPLAIN SELECT 1", 1)
	if v != nil {
		t.Errorf("custom-readonly should allow EXPLAIN, got %s", v.Reason)
	}

	// INSERT should be blocked (not in the custom allowlist)
	v = pe.CheckQuery(id("agent1", ""), "INSERT INTO t(a) VALUES(1)", 1)
	if v == nil {
		t.Error("custom-readonly should block INSERT")
	}

	// DELETE should be blocked
	v = pe.CheckQuery(id("agent1", ""), "DELETE FROM t WHERE id=1", 1)
	if v == nil {
		t.Error("custom-readonly should block DELETE")
	}
}

// ── Blocked tables still work with profiles ──

func TestProfileWithBlockedTables(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				Profile:       "permissive",
				BlockedTables: []string{"public.secrets"},
			},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "SELECT * FROM public.secrets", 1)
	if v == nil {
		t.Error("blocked table should still apply with profile")
	}
	if v.Reason != "blocked_table" {
		t.Errorf("expected blocked_table, got %s", v.Reason)
	}

	// Other tables should be fine
	v = pe.CheckQuery(id("agent1", ""), "SELECT * FROM public.feedback", 1)
	if v != nil {
		t.Errorf("non-blocked table should be allowed, got %s", v.Reason)
	}
}

// ── Mission conditions still work with legacy ──

func TestLegacyMissionConditions(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				Missions: map[string]MissionPolicy{
					"write-data": {
						Tables:     []string{"public.orders"},
						Conditions: []string{"UPDATE must include WHERE clause", "DELETE must include WHERE clause"},
					},
				},
			},
		},
	})

	// UPDATE without WHERE — blocked
	v := pe.CheckQuery(id("agent1", "write-data"), "UPDATE public.orders SET status='shipped'", 1)
	if v == nil {
		t.Error("mission condition should block UPDATE without WHERE")
	}

	// UPDATE with WHERE — allowed
	v = pe.CheckQuery(id("agent1", "write-data"), "UPDATE public.orders SET status='shipped' WHERE id=1", 1)
	if v != nil {
		t.Errorf("should allow UPDATE with WHERE, got %s", v.Reason)
	}
}

// ── Function blocklist works with profiles ──

func TestProfileWithBlockedFunctions(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy:   "deny",
		BlockedFunctions: []string{"pg_sleep"},
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "permissive"},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "SELECT pg_sleep(999)", 1)
	if v == nil {
		t.Error("global blocked function should still apply with profile")
	}
}

// ── Agent not in policy ──

func TestAgentNotInPolicyDeny(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents:        map[string]AgentPolicy{},
	})

	v := pe.CheckQuery(id("unknown-agent", ""), "SELECT 1", 1)
	if v == nil {
		t.Error("should deny agent not in policy when default=deny")
	}
	if v.Reason != "agent_not_in_policy" {
		t.Errorf("expected agent_not_in_policy, got %s", v.Reason)
	}
}

func TestAgentNotInPolicyAllow(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "allow",
		Agents:        map[string]AgentPolicy{},
	})

	v := pe.CheckQuery(id("unknown-agent", ""), "SELECT 1", 1)
	if v != nil {
		t.Error("should allow agent not in policy when default=allow")
	}
}

// ── ResolveProfile ──

func TestResolveProfileBuiltin(t *testing.T) {
	for _, name := range []string{"permissive", "standard", "strict"} {
		p := ResolveProfile(name, nil)
		if p == nil {
			t.Errorf("builtin profile %q should resolve", name)
		}
		if p.Name != name {
			t.Errorf("expected name %q, got %q", name, p.Name)
		}
	}
}

func TestResolveProfileUnknown(t *testing.T) {
	p := ResolveProfile("nonexistent", nil)
	if p != nil {
		t.Error("unknown profile should return nil")
	}
}

func TestResolveProfileCustom(t *testing.T) {
	cfg := &PolicyConfig{
		Profiles: map[string]CustomProfileConfig{
			"my-profile": {
				Extends:           "strict",
				AllowedOperations: []string{"SELECT"},
			},
		},
	}
	p := ResolveProfile("my-profile", cfg)
	if p == nil {
		t.Fatal("custom profile should resolve")
	}
	if len(p.AllowedOperations) != 1 || p.AllowedOperations[0] != "SELECT" {
		t.Errorf("expected AllowedOperations=[SELECT], got %v", p.AllowedOperations)
	}
}
