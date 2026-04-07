package main

import (
    "fmt"
    "strings"
    "testing"
)

func TestUnclassifiedBypasses(t *testing.T) {
    queries := []struct{name, q, want string}{
        {"ANY_ARRAY", "SELECT id FROM public.feedback WHERE rating = ANY(ARRAY[(SELECT count(*) FROM public.users)::int])", "users"},
        {"bool_and_subquery", "SELECT id FROM public.feedback WHERE (SELECT bool_and(amount > 0) FROM public.payments) IS TRUE", "payments"},
        {"IN_list_subqueries", "SELECT id FROM public.feedback WHERE rating IN ((SELECT count(*) FROM public.users), (SELECT count(*) FROM public.payments))", "users"},
        {"OFFSET_GREATEST", "SELECT id FROM public.feedback OFFSET GREATEST(0, (SELECT count(*) FROM public.users) - 1)", "users"},
        {"FETCH_FIRST_subquery", "SELECT id FROM public.feedback FETCH FIRST (SELECT count(*) FROM public.payments) ROWS ONLY", "payments"},
        {"CASE_in_ORDER_BY", "SELECT id FROM public.feedback ORDER BY CASE WHEN (SELECT password_hash FROM public.users LIMIT 1) IS NOT NULL THEN rating ELSE -rating END", "users"},
        {"window_frame_subquery", "SELECT id, sum(rating) OVER (ORDER BY id ROWS (SELECT count(*) FROM public.payments) PRECEDING) FROM public.feedback", "payments"},
    }
    for _, tt := range queries {
        t.Run(tt.name, func(t *testing.T) {
            pq := ParseQuery(tt.q)
            found := false
            for _, tbl := range pq.Tables {
                if strings.Contains(tbl, tt.want) { found = true }
            }
            if found {
                fmt.Printf("  ✅ %s: tables=%v\n", tt.name, pq.Tables)
            } else {
                fmt.Printf("  ❌ %s: tables=%v (missing %s)\n", tt.name, pq.Tables, tt.want)
                t.Errorf("Missing %s in %v", tt.want, pq.Tables)
            }
        })
    }
}
