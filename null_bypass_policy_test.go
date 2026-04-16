package main

import (
	"fmt"
	"testing"
)

func TestNullBytePolicy(t *testing.T) {
	q := "SELECT \x00 FROM public.users"
	
	// Step 1: Parse
	parsed := ParseQuery(q)
	fmt.Printf("Step 1 - ParseQuery:\n")
	fmt.Printf("  Operation: %s\n", parsed.Operation)
	fmt.Printf("  Tables: %v\n", parsed.Tables)
	fmt.Printf("  UsedAST: %v\n", parsed.UsedAST)
	
	if len(parsed.Tables) == 0 {
		t.Fatal("ParseQuery failed to detect any tables")
	}
	
	// Step 2: Check if isTableBlocked catches it
	blocked := []string{"public.users", "public.payments", "pg_catalog.*", "information_schema.*"}
	for _, tbl := range parsed.Tables {
		result := isTableBlocked(tbl, blocked)
		fmt.Printf("  isTableBlocked(%q, blocked) = %v\n", tbl, result)
		if tbl == "public.users" && !result {
			t.Error("isTableBlocked failed to catch public.users")
		}
	}
}
