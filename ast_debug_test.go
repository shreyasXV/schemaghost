package main

import (
	"fmt"
	"testing"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func TestDebugAST(t *testing.T) {
	// Test 1: Array subquery
	result, _ := pg_query.Parse("SELECT * FROM unnest(ARRAY(SELECT id FROM public.users))")
	fmt.Printf("=== ARRAY subquery ===\n%s\n\n", result.GetStmts()[0].GetStmt().String())
	
	// Test 2: Array subscript
	result2, _ := pg_query.Parse("SELECT (ARRAY(SELECT email FROM public.users))[1]")
	fmt.Printf("=== Array subscript ===\n%s\n\n", result2.GetStmts()[0].GetStmt().String())
	
	// Test 3: xpath(query_to_xml(...))
	result3, _ := pg_query.Parse("SELECT (xpath('//text()', query_to_xml('SELECT 1', true, false, '')))[1]::text")
	fmt.Printf("=== xpath ===\n%s\n\n", result3.GetStmts()[0].GetStmt().String())
	
	// Test 4: schema-qualified function
	result4, _ := pg_query.Parse("SELECT pg_catalog.pg_read_file('/etc/passwd')")
	fmt.Printf("=== schema-qualified ===\n%s\n\n", result4.GetStmts()[0].GetStmt().String())
}
