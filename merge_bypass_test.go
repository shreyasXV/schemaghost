package main

import (
    "fmt"
    "strings"
    "testing"
)

func TestMergeAndRemainingGaps(t *testing.T) {
    tests := []struct{
        name string
        query string
        wantTable string
    }{
        {"merge_source", "MERGE INTO products USING users ON products.id = users.id WHEN MATCHED THEN UPDATE SET name = users.email", "users"},
        {"merge_when_subquery", "MERGE INTO products USING (SELECT * FROM payments) AS p ON products.id = p.id WHEN MATCHED THEN DELETE", "payments"},
        {"merge_returning", "MERGE INTO products USING users ON products.id = users.id WHEN MATCHED THEN UPDATE SET name = 'x' RETURNING (SELECT email FROM users LIMIT 1)", "users"},
        {"coerce_domain", "SELECT name::text FROM products WHERE id = (SELECT id FROM users LIMIT 1)", "users"},
    }
    
    for _, tt := range tests {
        t.Run(tt.name, func(t *testing.T) {
            parsed := ParseQuery(tt.query)
            found := false
            for _, tbl := range parsed.Tables {
                if strings.Contains(strings.ToLower(tbl), tt.wantTable) {
                    found = true
                    break
                }
            }
            fmt.Printf("%s: tables=%v\n", tt.name, parsed.Tables)
            if !found {
                t.Errorf("MISSED table %q in: %s\ntables: %v", tt.wantTable, tt.query[:min(80, len(tt.query))], parsed.Tables)
            }
        })
    }
}

func min(a, b int) int {
    if a < b { return a }
    return b
}
