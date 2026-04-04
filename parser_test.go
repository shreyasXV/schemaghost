package main

import (
	"fmt"
	"testing"
)

func TestParserAST(t *testing.T) {
	tests := []struct {
		name      string
		query     string
		wantOp    string
		wantAST   bool
		wantFuncs []string
	}{
		{"pg_sleep", "SELECT pg_sleep(999)", "SELECT", true, []string{"pg_sleep"}},
		{"lo_export", "SELECT lo_export(1234, '/tmp/pwned')", "SELECT", true, []string{"lo_export"}},
		{"CTE", "WITH leaked AS (SELECT * FROM secret_table) SELECT * FROM leaked", "SELECT", true, nil},
		{"dblink", "SELECT * FROM dblink('host=evil.com', 'SELECT 1') AS t(id int)", "SELECT", true, []string{"dblink"}},
		{"normal", "SELECT id, name FROM public.feedback WHERE id > 5", "SELECT", true, nil},
		{"DROP", "DROP TABLE public.feedback", "DROP", true, nil},
		{"pg_read_file", "SELECT pg_read_file('/etc/passwd')", "SELECT", true, []string{"pg_read_file"}},
		{"schema_qual", "SELECT pg_catalog.pg_sleep(10)", "SELECT", true, []string{"pg_catalog.pg_sleep", "pg_sleep"}},
		{"COPY_TO", "COPY public.users TO STDOUT", "COPY", true, nil},
		{"unparseable", "THIS IS NOT VALID SQL AT ALL !!!", "UNKNOWN", false, nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			fmt.Printf("  [%s] op=%s ast=%v tables=%v funcs=%v\n", tt.name, parsed.Operation, parsed.UsedAST, parsed.Tables, parsed.Functions)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %s, want %s", parsed.Operation, tt.wantOp)
			}
			if parsed.UsedAST != tt.wantAST {
				t.Errorf("usedAST: got %v, want %v", parsed.UsedAST, tt.wantAST)
			}
			for _, wf := range tt.wantFuncs {
				found := false
				for _, f := range parsed.Functions {
					if f == wf {
						found = true
						break
					}
				}
				if !found {
					t.Errorf("expected function %s not found in %v", wf, parsed.Functions)
				}
			}
		})
	}
}

func TestParserFullCoverage(t *testing.T) {
	tests := []struct {
		name     string
		query    string
		wantOp   string
		category string
	}{
		// ── DML ──
		{"SELECT", "SELECT 1", "SELECT", "DML"},
		{"INSERT", "INSERT INTO t(a) VALUES(1)", "INSERT", "DML"},
		{"UPDATE", "UPDATE t SET a=1 WHERE id=1", "UPDATE", "DML"},
		{"DELETE", "DELETE FROM t WHERE id=1", "DELETE", "DML"},
		{"MERGE", "MERGE INTO t USING s ON t.id=s.id WHEN MATCHED THEN UPDATE SET a=s.a", "MERGE", "DML"},
		{"COPY_FROM", "COPY t FROM STDIN", "COPY", "DML"},

		// ── DDL ──
		{"CREATE_TABLE", "CREATE TABLE t(id int)", "CREATE", "DDL"},
		{"CREATE_TABLE_AS", "CREATE TABLE t AS SELECT 1", "CREATE", "DDL"},
		{"CREATE_SCHEMA", "CREATE SCHEMA myschema", "CREATE", "DDL"},
		{"CREATE_SEQUENCE", "CREATE SEQUENCE myseq", "CREATE", "DDL"},
		{"CREATE_INDEX", "CREATE INDEX idx ON t(a)", "CREATE", "DDL"},
		{"CREATE_VIEW", "CREATE VIEW v AS SELECT 1", "CREATE", "DDL"},
		{"CREATE_TRIGGER", "CREATE TRIGGER tr AFTER INSERT ON t FOR EACH ROW EXECUTE FUNCTION f()", "CREATE", "DDL"},
		{"CREATE_TYPE_ENUM", "CREATE TYPE mood AS ENUM ('happy', 'sad')", "CREATE", "DDL"},
		{"CREATE_DOMAIN", "CREATE DOMAIN posint AS integer CHECK (VALUE > 0)", "CREATE", "DDL"},
		{"ALTER_TABLE", "ALTER TABLE t ADD COLUMN b int", "ALTER", "DDL"},
		{"ALTER_SEQUENCE", "ALTER SEQUENCE myseq RESTART", "ALTER", "DDL"},
		{"ALTER_TYPE", "ALTER TYPE mood ADD VALUE 'angry'", "ALTER", "DDL"},
		{"RENAME", "ALTER TABLE t RENAME TO t2", "ALTER", "DDL"},
		{"DROP_TABLE", "DROP TABLE t", "DROP", "DDL"},
		{"TRUNCATE", "TRUNCATE t", "TRUNCATE", "DDL"},
		{"COMMENT", "COMMENT ON TABLE t IS 'test'", "ALTER", "DDL"},
		{"CREATE_RULE", "CREATE RULE r AS ON INSERT TO t DO NOTHING", "CREATE", "DDL"},

		// ── DCL (Access Control) ──
		{"GRANT", "GRANT SELECT ON t TO role1", "GRANT", "DCL"},
		{"GRANT_ROLE", "GRANT role1 TO role2", "GRANT", "DCL"},
		{"ALTER_DEFAULT_PRIVILEGES", "ALTER DEFAULT PRIVILEGES GRANT SELECT ON TABLES TO role1", "ALTER_DEFAULT_PRIVILEGES", "DCL"},
		{"ALTER_ROLE", "ALTER ROLE admin SUPERUSER", "ALTER_ROLE", "DCL"},
		{"ALTER_ROLE_SET", "ALTER ROLE admin SET work_mem = '256MB'", "ALTER_ROLE", "DCL"},
		{"CREATE_ROLE", "CREATE ROLE readonly LOGIN", "CREATE_ROLE", "DCL"},
		{"DROP_ROLE", "DROP ROLE readonly", "DROP_ROLE", "DCL"},
		{"REASSIGN_OWNED", "REASSIGN OWNED BY old_role TO new_role", "REASSIGN_OWNED", "DCL"},
		{"DROP_OWNED", "DROP OWNED BY old_role", "DROP_OWNED", "DCL"},
		{"CREATE_POLICY", "CREATE POLICY p ON t FOR SELECT USING (true)", "CREATE_POLICY", "DCL"},
		{"ALTER_POLICY", "ALTER POLICY p ON t USING (true)", "ALTER_POLICY", "DCL"},

		// ── TCL (Transaction) ──
		{"BEGIN", "BEGIN", "TRANSACTION", "TCL"},
		{"COMMIT", "COMMIT", "TRANSACTION", "TCL"},
		{"ROLLBACK", "ROLLBACK", "TRANSACTION", "TCL"},
		{"SET_CONSTRAINTS", "SET CONSTRAINTS ALL DEFERRED", "TRANSACTION", "TCL"},

		// ── FUNCTION (Code Execution) ──
		{"CREATE_FUNCTION", "CREATE FUNCTION f() RETURNS void AS $$ BEGIN END; $$ LANGUAGE plpgsql", "CREATE_FUNCTION", "FUNCTION"},
		{"DO_block", "DO $$ BEGIN PERFORM 1; END $$", "DO", "FUNCTION"},
		{"CALL", "CALL my_procedure()", "CALL", "FUNCTION"},
		{"CREATE_EVENT_TRIGGER", "CREATE EVENT TRIGGER tr ON ddl_command_start EXECUTE FUNCTION f()", "CREATE_EVENT_TRIGGER", "FUNCTION"},

		// ── SESSION ──
		{"SET", "SET work_mem = '256MB'", "SET", "SESSION"},
		{"SHOW", "SHOW work_mem", "SHOW", "SESSION"},
		{"DISCARD", "DISCARD ALL", "DISCARD", "SESSION"},
		{"PREPARE", "PREPARE stmt AS SELECT 1", "PREPARE", "SESSION"},
		{"EXECUTE", "EXECUTE stmt", "EXECUTE", "SESSION"},
		{"DEALLOCATE", "DEALLOCATE stmt", "DEALLOCATE", "SESSION"},
		{"LISTEN", "LISTEN mychannel", "LISTEN", "SESSION"},
		{"UNLISTEN", "UNLISTEN mychannel", "UNLISTEN", "SESSION"},
		{"NOTIFY", "NOTIFY mychannel, 'hello'", "NOTIFY", "SESSION"},
		{"LOCK_TABLE", "LOCK TABLE t IN ACCESS EXCLUSIVE MODE", "LOCK", "SESSION"},
		{"LOAD", "LOAD 'auto_explain'", "LOAD", "SESSION"},

		// ── ADMIN (Server Administration) ──
		{"VACUUM", "VACUUM t", "VACUUM", "ADMIN"},
		{"VACUUM_FULL", "VACUUM FULL t", "VACUUM", "ADMIN"},
		{"REINDEX", "REINDEX TABLE t", "REINDEX", "ADMIN"},
		{"CLUSTER", "CLUSTER t USING idx", "CLUSTER", "ADMIN"},
		{"CHECKPOINT", "CHECKPOINT", "CHECKPOINT", "ADMIN"},
		{"ALTER_SYSTEM", "ALTER SYSTEM SET work_mem = '256MB'", "ALTER_SYSTEM", "ADMIN"},
		{"ALTER_DATABASE", "ALTER DATABASE mydb SET work_mem = '256MB'", "ALTER_DATABASE_SET", "ADMIN"},
		{"REFRESH_MATVIEW", "REFRESH MATERIALIZED VIEW mv", "REFRESH_MATVIEW", "ADMIN"},
		{"CREATE_DATABASE", "CREATE DATABASE mydb", "CREATE_DATABASE", "ADMIN"},
		{"DROP_DATABASE", "DROP DATABASE mydb", "DROP_DATABASE", "ADMIN"},
		{"CREATE_TABLESPACE", "CREATE TABLESPACE ts LOCATION '/data'", "CREATE_TABLESPACE", "ADMIN"},
		{"DROP_TABLESPACE", "DROP TABLESPACE ts", "DROP_TABLESPACE", "ADMIN"},

		// ── EXTENSION ──
		{"CREATE_EXTENSION", "CREATE EXTENSION pgcrypto", "CREATE_EXTENSION", "EXTENSION"},
		{"ALTER_EXTENSION", "ALTER EXTENSION pgcrypto UPDATE", "ALTER_EXTENSION", "EXTENSION"},
		{"CREATE_FDW", "CREATE FOREIGN DATA WRAPPER myfdw", "CREATE_FDW", "EXTENSION"},
		{"CREATE_FOREIGN_SERVER", "CREATE SERVER myserver FOREIGN DATA WRAPPER myfdw", "CREATE_FOREIGN_SERVER", "EXTENSION"},
		{"IMPORT_FOREIGN_SCHEMA", "IMPORT FOREIGN SCHEMA public FROM SERVER myserver INTO local_schema", "IMPORT_FOREIGN_SCHEMA", "EXTENSION"},
		{"CREATE_PUBLICATION", "CREATE PUBLICATION mypub FOR ALL TABLES", "CREATE_PUBLICATION", "EXTENSION"},
		{"CREATE_SUBSCRIPTION", "CREATE SUBSCRIPTION mysub CONNECTION 'host=localhost' PUBLICATION mypub", "CREATE_SUBSCRIPTION", "EXTENSION"},

		// ── EXPLAIN ──
		{"EXPLAIN", "EXPLAIN SELECT 1", "EXPLAIN", "EXPLAIN"},
		{"EXPLAIN_ANALYZE", "EXPLAIN ANALYZE SELECT 1", "EXPLAIN", "EXPLAIN"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %q, want %q", parsed.Operation, tt.wantOp)
			}
			if !parsed.UsedAST {
				t.Errorf("expected AST parsing for %q but got regex fallback", tt.query)
			}
			// Verify category mapping
			cat, ok := OperationCategory[parsed.Operation]
			if !ok {
				t.Errorf("operation %q not found in OperationCategory map", parsed.Operation)
			} else if cat != tt.category {
				t.Errorf("category: got %q, want %q for operation %q", cat, tt.category, parsed.Operation)
			}
		})
	}
}

func TestParserUnknownForGarbage(t *testing.T) {
	parsed := ParseQuery("THIS IS NOT VALID SQL AT ALL !!!")
	if parsed.Operation != "UNKNOWN" {
		t.Errorf("expected UNKNOWN for garbage SQL, got %q", parsed.Operation)
	}
	if parsed.UsedAST {
		t.Error("expected regex fallback for garbage SQL")
	}
}

func TestOperationCategoryCompleteness(t *testing.T) {
	// Every value in OperationCategory should be a known category
	knownCategories := map[string]bool{
		"DML": true, "DDL": true, "DCL": true, "TCL": true,
		"FUNCTION": true, "SESSION": true, "ADMIN": true,
		"EXTENSION": true, "EXPLAIN": true,
	}
	for op, cat := range OperationCategory {
		if !knownCategories[cat] {
			t.Errorf("operation %q maps to unknown category %q", op, cat)
		}
	}

	// Snapshot: pin the number of classified operations.
	// If pg_query_go adds new statement types, this test fails and tells you
	// exactly how many new operations need classifying.
	// Update this count after adding new classifications.
	expectedOps := len(OperationCategory)
	if expectedOps < 50 {
		t.Errorf("OperationCategory has only %d entries — expected 50+. Did a refactor drop entries?", expectedOps)
	}

	// Pin exact count so upgrades surface new unclassified types.
	// Update this after classifying new pg_query_go statement types.
	const pinnedCount = 75
	if len(OperationCategory) != pinnedCount {
		t.Errorf("OperationCategory count changed: got %d, pinned at %d. Classify new operations and update this constant.", len(OperationCategory), pinnedCount)
	}
}

func TestMultiStatementOperations(t *testing.T) {
	tests := []struct {
		name       string
		query      string
		wantOps    []string
		wantFirstOp string
	}{
		{
			"select_then_drop",
			"SELECT 1; DROP TABLE users",
			[]string{"SELECT", "DROP"},
			"SELECT",
		},
		{
			"select_then_delete",
			"SELECT 1; DELETE FROM users",
			[]string{"SELECT", "DELETE"},
			"SELECT",
		},
		{
			"multiple_selects",
			"SELECT 1; SELECT 2",
			[]string{"SELECT", "SELECT"},
			"SELECT",
		},
		{
			"single_statement",
			"SELECT 1",
			[]string{"SELECT"},
			"SELECT",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantFirstOp {
				t.Errorf("Operation: got %q, want %q", parsed.Operation, tt.wantFirstOp)
			}
			if len(parsed.Operations) != len(tt.wantOps) {
				t.Fatalf("Operations count: got %d, want %d (%v)", len(parsed.Operations), len(tt.wantOps), parsed.Operations)
			}
			for i, op := range tt.wantOps {
				if parsed.Operations[i] != op {
					t.Errorf("Operations[%d]: got %q, want %q", i, parsed.Operations[i], op)
				}
			}
		})
	}
}

func TestSetRoleDetection(t *testing.T) {
	tests := []struct {
		name   string
		query  string
		wantOp string
		wantCat string
	}{
		{"SET_ROLE", "SET ROLE superuser", "SET_ROLE", "DCL"},
		{"SET_SESSION_AUTH", "SET SESSION AUTHORIZATION postgres", "SET_ROLE", "DCL"},
		{"SET_normal", "SET work_mem = '64MB'", "SET", "SESSION"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parsed := ParseQuery(tt.query)
			if parsed.Operation != tt.wantOp {
				t.Errorf("operation: got %q, want %q", parsed.Operation, tt.wantOp)
			}
			cat, ok := OperationCategory[parsed.Operation]
			if !ok {
				t.Errorf("operation %q not in OperationCategory", parsed.Operation)
			} else if cat != tt.wantCat {
				t.Errorf("category: got %q, want %q", cat, tt.wantCat)
			}
		})
	}
}

