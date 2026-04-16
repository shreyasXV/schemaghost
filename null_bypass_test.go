package main

import (
	"fmt"
	"testing"
)

func TestNullByteBypass(t *testing.T) {
	q := "SELECT \x00 FROM public.users"
	parsed := ParseQuery(q)
	fmt.Printf("Operation: %s\n", parsed.Operation)
	fmt.Printf("Tables: %v\n", parsed.Tables)
	fmt.Printf("UsedAST: %v\n", parsed.UsedAST)
	fmt.Printf("Operations: %v\n", parsed.Operations)
	
	found := false
	for _, tbl := range parsed.Tables {
		if tbl == "public.users" || tbl == "users" {
			found = true
		}
	}
	if !found {
		t.Errorf("Expected public.users in tables, got: %v", parsed.Tables)
	}
}
