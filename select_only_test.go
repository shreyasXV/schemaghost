package main

import (
	"fmt"
	"testing"
)

func TestSelectAlone(t *testing.T) {
	for _, q := range []string{"SELECT", "SELECT ", "SELECT  FROM public.users"} {
		parsed := ParseQuery(q)
		fmt.Printf("Query: %q → Op=%s Tables=%v UsedAST=%v\n", q, parsed.Operation, parsed.Tables, parsed.UsedAST)
	}
}
