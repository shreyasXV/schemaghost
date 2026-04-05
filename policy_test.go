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

// ── Multi-statement bypass prevention ──

func TestMultiStatementBypass(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {
				BlockedOperations: []string{"DROP", "DELETE"},
			},
		},
	})

	// "SELECT 1; DROP TABLE users" should be blocked because DROP is blocked
	v := pe.CheckQuery(id("agent1", ""), "SELECT 1; DROP TABLE users", 1)
	if v == nil {
		t.Error("multi-statement with DROP should be blocked")
	} else if v.Operation != "DROP" {
		t.Errorf("expected violation on DROP, got %s", v.Operation)
	}

	// "SELECT 1; DELETE FROM users" should be blocked because DELETE is blocked
	v = pe.CheckQuery(id("agent1", ""), "SELECT 1; DELETE FROM users WHERE id=1", 1)
	if v == nil {
		t.Error("multi-statement with DELETE should be blocked")
	}

	// "SELECT 1; SELECT 2" should pass
	v = pe.CheckQuery(id("agent1", ""), "SELECT 1; SELECT 2", 1)
	if v != nil {
		t.Errorf("multi-statement SELECT;SELECT should pass, got violation: %s", v.Reason)
	}
}

func TestMultiStatementBypassWithProfile(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	// "SELECT 1; VACUUM t" — standard blocks ADMIN category
	v := pe.CheckQuery(id("agent1", ""), "SELECT 1; VACUUM t", 1)
	if v == nil {
		t.Error("standard profile should block multi-statement with VACUUM (ADMIN)")
	}

	// "SELECT 1; GRANT SELECT ON t TO role1" — standard blocks DCL
	v = pe.CheckQuery(id("agent1", ""), "SELECT 1; GRANT SELECT ON t TO role1", 1)
	if v == nil {
		t.Error("standard profile should block multi-statement with GRANT")
	}

	// "SELECT 1; SELECT 2" should pass
	v = pe.CheckQuery(id("agent1", ""), "SELECT 1; SELECT 2", 1)
	if v != nil {
		t.Errorf("multi-statement SELECT;SELECT should pass with standard, got: %s", v.Reason)
	}
}

func TestSetRoleBlockedByStandardProfile(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	// SET ROLE is DCL — standard blocks DCL
	v := pe.CheckQuery(id("agent1", ""), "SET ROLE superuser", 1)
	if v == nil {
		t.Error("standard profile should block SET ROLE (DCL)")
	}

	// SET SESSION AUTHORIZATION is also DCL
	v = pe.CheckQuery(id("agent1", ""), "SET SESSION AUTHORIZATION postgres", 1)
	if v == nil {
		t.Error("standard profile should block SET SESSION AUTHORIZATION (DCL)")
	}

	// Regular SET should still be allowed (SESSION category)
	v = pe.CheckQuery(id("agent1", ""), "SET work_mem = '256MB'", 1)
	if v != nil {
		t.Errorf("standard profile should allow regular SET, got: %s", v.Reason)
	}
}

// ── Red-team round 5: Wildcard function matching ──

func TestWildcardFunctionBlocking(t *testing.T) {
	tests := []struct {
		name    string
		fn      string
		blocked []string
		want    bool
	}{
		{"exact_match", "pg_sleep", []string{"pg_sleep"}, true},
		{"wildcard_lo", "lo_export", []string{"lo_*"}, true},
		{"wildcard_lo_import", "lo_import", []string{"lo_*"}, true},
		{"wildcard_lo_create", "lo_create", []string{"lo_*"}, true},
		{"wildcard_pg_stat_get", "pg_stat_get_activity", []string{"pg_stat_get_*"}, true},
		{"wildcard_dblink", "dblink_exec", []string{"dblink*"}, true},
		{"wildcard_dblink_connect", "dblink_connect", []string{"dblink*"}, true},
		{"wildcard_dblink_bare", "dblink", []string{"dblink*"}, true},
		{"wildcard_no_match", "pg_sleep", []string{"lo_*"}, false},
		{"wildcard_advisory_lock", "pg_advisory_lock", []string{"pg_advisory_lock*"}, true},
		{"wildcard_try_advisory", "pg_try_advisory_lock", []string{"pg_try_advisory_lock*"}, true},
		{"schema_qualified_wildcard", "pg_catalog.lo_export", []string{"lo_*"}, true},
		{"query_to_xml_wildcard", "query_to_xml_and_xmlschema", []string{"query_to_xml*"}, true},
		{"not_blocked", "count", []string{"pg_sleep", "lo_*"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isFunctionBlocked(tt.fn, tt.blocked)
			if got != tt.want {
				t.Errorf("isFunctionBlocked(%q, %v) = %v, want %v", tt.fn, tt.blocked, got, tt.want)
			}
		})
	}
}

// ── Red-team round 5: Expanded blocklist coverage ──

func TestExpandedBlocklistCoverage(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		BlockedFunctions: []string{
			"pg_sleep", "version", "current_setting", "pg_advisory_lock*",
			"pg_try_advisory_lock*",
			"generate_series", "repeat", "lo_*", "pg_stat_get_*",
			"pg_backend_pid", "pg_typeof", "has_table_privilege",
			"dblink*", "set_config",
		},
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "permissive"},
		},
	})

	blocked := []struct {
		query string
		desc  string
	}{
		{"SELECT version()", "version() recon"},
		{"SELECT current_setting('server_version')", "current_setting recon"},
		{"SELECT pg_advisory_lock(1)", "advisory lock DoS"},
		{"SELECT pg_try_advisory_lock(1)", "try advisory lock"},  // not matching pg_advisory_lock* — separate pattern needed
		{"SELECT generate_series(1, 1000000000)", "generate_series resource exhaustion"},
		{"SELECT repeat('A', 1000000000)", "repeat resource exhaustion"},
		{"SELECT lo_export(1234, '/tmp/pwned')", "lo_export via wildcard"},
		{"SELECT lo_import('/etc/passwd')", "lo_import via wildcard"},
		{"SELECT pg_stat_get_activity(NULL)", "pg_stat_get via wildcard"},
		{"SELECT pg_backend_pid()", "pg_backend_pid recon"},
		{"SELECT pg_typeof(1)", "pg_typeof type inspection"},
		{"SELECT has_table_privilege('public.users', 'SELECT')", "privilege check info leak"},
		{"SELECT * FROM dblink('host=evil.com', 'SELECT 1') AS t(id int)", "dblink remote connection"},
		{"SELECT set_config('log_connections', 'off', false)", "set_config manipulation"},
	}

	for _, tt := range blocked {
		t.Run(tt.desc, func(t *testing.T) {
			v := pe.CheckQuery(id("agent1", ""), tt.query, 1)
			if v == nil {
				t.Errorf("expected %s to be blocked: %s", tt.desc, tt.query)
			}
		})
	}
}

// ── Red-team round 5: regproc cast blocking ──

func TestRegprocCastBlocking(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy:    "deny",
		BlockedFunctions: []string{"pg_sleep", "lo_export", "lo_*"},
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "permissive"},
		},
	})

	tests := []struct {
		query string
		desc  string
	}{
		{"SELECT 'pg_sleep'::regproc", "regproc cast pg_sleep"},
		{"SELECT 'lo_export'::regproc", "regproc cast lo_export"},
	}

	for _, tt := range tests {
		t.Run(tt.desc, func(t *testing.T) {
			v := pe.CheckQuery(id("agent1", ""), tt.query, 1)
			if v == nil {
				t.Errorf("expected %s to be blocked", tt.desc)
			}
		})
	}
}

// ── Red-team round 5: Trivial WHERE detection ──

func TestTrivialWhereDetection(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	trivialDeletes := []struct {
		query string
		desc  string
	}{
		{"DELETE FROM t WHERE 1=1", "WHERE 1=1"},
		{"DELETE FROM t WHERE true", "WHERE true"},
		{"DELETE FROM t WHERE 1 = 1", "WHERE 1 = 1"},
		{"DELETE FROM t WHERE NOT FALSE", "WHERE NOT FALSE"},
		{"DELETE FROM t WHERE 1 > 0", "WHERE 1 > 0"},
		{"DELETE FROM t WHERE 1 >= 1", "WHERE 1 >= 1"},
		{"DELETE FROM t", "no WHERE at all"},
	}

	for _, tt := range trivialDeletes {
		t.Run("blocked_"+tt.desc, func(t *testing.T) {
			v := pe.CheckQuery(id("agent1", ""), tt.query, 1)
			if v == nil {
				t.Errorf("expected DELETE with %s to be blocked", tt.desc)
			} else if v.Reason != "condition_violated" {
				t.Errorf("expected condition_violated, got %s", v.Reason)
			}
		})
	}

	// Trivial UPDATE should also be blocked
	trivialUpdates := []struct {
		query string
		desc  string
	}{
		{"UPDATE t SET a=1 WHERE 1=1", "UPDATE WHERE 1=1"},
		{"UPDATE t SET a=1 WHERE true", "UPDATE WHERE true"},
	}

	for _, tt := range trivialUpdates {
		t.Run("blocked_"+tt.desc, func(t *testing.T) {
			v := pe.CheckQuery(id("agent1", ""), tt.query, 1)
			if v == nil {
				t.Errorf("expected %s to be blocked", tt.desc)
			}
		})
	}

	// Legitimate WHERE should pass
	v := pe.CheckQuery(id("agent1", ""), "DELETE FROM t WHERE id = 42", 1)
	if v != nil {
		t.Errorf("legitimate DELETE with WHERE should pass, got %s", v.Reason)
	}

	v = pe.CheckQuery(id("agent1", ""), "UPDATE t SET a=1 WHERE id = 42", 1)
	if v != nil {
		t.Errorf("legitimate UPDATE with WHERE should pass, got %s", v.Reason)
	}
}

// ── Red-team round 5: NOTIFY blocked by standard ──

func TestNotifyBlockedByStandard(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "NOTIFY mychannel, 'exfil data here'", 1)
	if v == nil {
		t.Error("standard should block NOTIFY (data exfiltration)")
	}

	// LISTEN should also be blocked
	v = pe.CheckQuery(id("agent1", ""), "LISTEN mychannel", 1)
	if v == nil {
		t.Error("standard should block LISTEN")
	}
}

// ── Red-team round 5: LOAD blocked by standard (via ADMIN category) ──

func TestLoadBlockedByStandard(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "LOAD 'auto_explain'", 1)
	if v == nil {
		t.Error("standard should block LOAD (now ADMIN category)")
	}
}

// ── Red-team round 5: DISCARD blocked by standard ──

func TestDiscardBlockedByStandard(t *testing.T) {
	pe := newTestEngine(&PolicyConfig{
		DefaultPolicy: "deny",
		Agents: map[string]AgentPolicy{
			"agent1": {Profile: "standard"},
		},
	})

	v := pe.CheckQuery(id("agent1", ""), "DISCARD ALL", 1)
	if v == nil {
		t.Error("standard should block DISCARD ALL")
	}
}

// ── Red-team round 5: hasTrivialWhere unit tests ──

func TestHasTrivialWhereUnit(t *testing.T) {
	tests := []struct {
		query string
		want  bool
	}{
		{"DELETE FROM t WHERE 1=1", true},
		{"DELETE FROM t WHERE 1 = 1", true},
		{"DELETE FROM t WHERE TRUE", true},
		{"DELETE FROM t WHERE NOT FALSE", true},
		{"delete from t where true", true},
		{"DELETE FROM t WHERE id = 42", false},
		{"DELETE FROM t WHERE name = 'test'", false},
		{"DELETE FROM t", false}, // no WHERE at all
		{"SELECT 1", false},     // no WHERE
		{"DELETE FROM t WHERE '1'='1'", true},
		{"DELETE FROM t WHERE 1<>0", true},
		{"DELETE FROM t WHERE 0 < 1", true},
	}

	for _, tt := range tests {
		t.Run(tt.query, func(t *testing.T) {
			got := hasTrivialWhere(tt.query)
			if got != tt.want {
				t.Errorf("hasTrivialWhere(%q) = %v, want %v", tt.query, got, tt.want)
			}
		})
	}
}
