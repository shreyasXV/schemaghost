package main

import (
	"fmt"
	"testing"
)

func TestDebugGrant(t *testing.T) {
	queries := []string{
		"GRANT ALL ON ALL TABLES TO public",
		"SELECT 1; GRANT ALL ON ALL TABLES IN SCHEMA public TO public",
	}
	for _, q := range queries {
		p := ParseQuery(q)
		fmt.Printf("Query: %s\n  Ops: %v  AST: %v\n\n", q, p.Operations, p.UsedAST)
	}
}
