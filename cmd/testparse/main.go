package main

import (
	"fmt"
	faultwall "github.com/shreyasXV/faultwall"
)

func main() {
	q := "SELECT \x00 FROM public.users"
	parsed := faultwall.ParseQuery(q)
	fmt.Printf("Operation: %s\n", parsed.Operation)
	fmt.Printf("Tables: %v\n", parsed.Tables)
	fmt.Printf("UsedAST: %v\n", parsed.UsedAST)
	fmt.Printf("Functions: %v\n", parsed.Functions)
	fmt.Printf("Operations: %v\n", parsed.Operations)
}
