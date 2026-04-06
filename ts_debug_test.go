package main

import (
	"fmt"
	"testing"
)

func TestDebugTablesample(t *testing.T) {
	q := "SELECT * FROM public.feedback TABLESAMPLE BERNOULLI(100) WHERE 1=1"
	p := ParseQuery(q)
	fmt.Printf("Tables: %v  Funcs: %v\n", p.Tables, p.Functions)
}
