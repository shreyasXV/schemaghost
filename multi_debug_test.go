package main

import (
	"fmt"
	"testing"
)

func TestDebugMultiStmt(t *testing.T) {
	queries := []string{
		"SELECT 1; DROP TABLE public.feedback",
		"SELECT 1; GRANT ALL ON ALL TABLES TO public",
		"SELECT * FROM public.feedback WHERE id = 1; DROP TABLE public.feedback--",
		"SELECT 1; TRUNCATE TABLE public.feedback;",
	}
	for _, q := range queries {
		p := ParseQuery(q)
		fmt.Printf("Query: %s\n  Ops: %v\n  Tables: %v\n  Funcs: %v\n\n", q, p.Operations, p.Tables, p.Functions)
	}
}
