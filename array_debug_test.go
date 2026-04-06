package main

import (
	"fmt"
	"testing"
)

func TestDebugArraySubquery(t *testing.T) {
	queries := []string{
		"SELECT * FROM unnest(ARRAY(SELECT id FROM public.users))",
		"SELECT (ARRAY(SELECT email FROM public.users))[1] FROM public.feedback WHERE 1=1",
		"SELECT * FROM json_to_recordset((SELECT json_agg(row_to_json(u)) FROM public.users u)::json) AS x(id int, email text) WHERE 1=1",
		"SELECT (xpath('//text()', query_to_xml('SELECT email FROM public.users LIMIT 5', false, false, '')))[1]::text WHERE 1=1",
		"SELECT (regexp_matches(pg_catalog.pg_read_file('/etc/passwd'), '([^\\n]+)', 'g'))[1]",
	}
	for _, q := range queries {
		p := ParseQuery(q)
		fmt.Printf("Query: %.80s...\n  Tables: %v\n  Funcs: %v\n  RegprocCast: %v\n\n", q, p.Tables, p.Functions, p.HasRegprocCast)
	}
}
