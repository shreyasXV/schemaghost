package main

import (
	"fmt"
	"testing"
	pg_query "github.com/pganalyze/pg_query_go/v6"
)

func TestDebugTablesampleAST(t *testing.T) {
	result, _ := pg_query.Parse("SELECT * FROM public.feedback TABLESAMPLE BERNOULLI(100) WHERE 1=1")
	fmt.Println(result.GetStmts()[0].GetStmt().String())
}
