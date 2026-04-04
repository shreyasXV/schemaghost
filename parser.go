package main

import (
	"log"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// ParsedQuery holds AST-extracted information about a SQL query
type ParsedQuery struct {
	Operation string
	Tables    []string
	Functions []string
	UsedAST   bool
}

// ParseQuery parses a SQL query using pg_query_go AST parser.
// Falls back to regex-based parsing if AST parsing fails.
func ParseQuery(query string) *ParsedQuery {
	// Strip leading SET statements before parsing
	normalized := stripLeadingSET(query)

	tree, err := pg_query.Parse(normalized)
	if err != nil {
		log.Printf("[REGEX-FALLBACK] AST parse failed for query: %v", err)
		return &ParsedQuery{
			Operation: ExtractSQLOperationRegex(query),
			Tables:    ExtractTablesRegex(query),
			Functions: nil,
			UsedAST:   false,
		}
	}

	pq := &ParsedQuery{UsedAST: true}

	if len(tree.Stmts) == 0 {
		return pq
	}

	// Extract from all statements (handles multi-statement queries)
	for i, rawStmt := range tree.Stmts {
		stmt := rawStmt.GetStmt()
		if stmt == nil {
			continue
		}
		// Operation comes from the first non-trivial statement
		if i == 0 {
			pq.Operation = extractOperationFromNode(stmt)
		}
		extractTablesFromNode(stmt, &pq.Tables)
		extractFunctionsFromNode(stmt, &pq.Functions)
	}

	// Deduplicate tables and functions
	pq.Tables = dedup(pq.Tables)
	pq.Functions = dedup(pq.Functions)

	return pq
}

// extractOperationFromNode determines the SQL operation type from an AST node
func extractOperationFromNode(node *pg_query.Node) string {
	switch {
	case node.GetSelectStmt() != nil:
		return "SELECT"
	case node.GetInsertStmt() != nil:
		return "INSERT"
	case node.GetUpdateStmt() != nil:
		return "UPDATE"
	case node.GetDeleteStmt() != nil:
		return "DELETE"
	case node.GetDropStmt() != nil:
		return "DROP"
	case node.GetCreateStmt() != nil:
		return "CREATE"
	case node.GetAlterTableStmt() != nil:
		return "ALTER"
	case node.GetTruncateStmt() != nil:
		return "TRUNCATE"
	case node.GetGrantStmt() != nil:
		return "GRANT"
	case node.GetCopyStmt() != nil:
		return "COPY"
	case node.GetExplainStmt() != nil:
		return "EXPLAIN"
	case node.GetAlterRoleStmt() != nil:
		return "ALTER"
	case node.GetAlterRoleSetStmt() != nil:
		return "ALTER"
	case node.GetCreateRoleStmt() != nil:
		return "CREATE"
	case node.GetDropRoleStmt() != nil:
		return "DROP"
	case node.GetGrantRoleStmt() != nil:
		return "GRANT"
	case node.GetReassignOwnedStmt() != nil:
		return "REASSIGN"
	case node.GetAlterSystemStmt() != nil:
		return "ALTER"
	case node.GetDoStmt() != nil:
		return "DO"
	default:
		return "UNKNOWN"
	}
}

// extractTablesFromNode recursively walks the AST to find all table references
func extractTablesFromNode(node *pg_query.Node, tables *[]string) {
	if node == nil {
		return
	}

	// RangeVar = direct table reference
	if rv := node.GetRangeVar(); rv != nil {
		name := ""
		if rv.Schemaname != "" {
			name = strings.ToLower(rv.Schemaname) + "." + strings.ToLower(rv.Relname)
		} else {
			name = strings.ToLower(rv.Relname)
		}
		if name != "" {
			*tables = append(*tables, name)
		}
	}

	// SelectStmt
	if sel := node.GetSelectStmt(); sel != nil {
		for _, from := range sel.FromClause {
			extractTablesFromNode(from, tables)
		}
		if sel.WhereClause != nil {
			extractTablesFromNode(sel.WhereClause, tables)
		}
		for _, target := range sel.TargetList {
			extractTablesFromNode(target, tables)
		}
		// CTEs
		if sel.WithClause != nil {
			for _, cte := range sel.WithClause.Ctes {
				if c := cte.GetCommonTableExpr(); c != nil {
					extractTablesFromNode(c.Ctequery, tables)
				}
			}
		}
		// UNION / INTERSECT / EXCEPT
		if sel.Larg != nil {
			larg := &pg_query.Node{}
			larg.Node = &pg_query.Node_SelectStmt{SelectStmt: sel.Larg}
			extractTablesFromNode(larg, tables)
		}
		if sel.Rarg != nil {
			rarg := &pg_query.Node{}
			rarg.Node = &pg_query.Node_SelectStmt{SelectStmt: sel.Rarg}
			extractTablesFromNode(rarg, tables)
		}
	}

	// InsertStmt
	if ins := node.GetInsertStmt(); ins != nil {
		if ins.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: ins.Relation}
			extractTablesFromNode(rv, tables)
		}
		if ins.SelectStmt != nil {
			extractTablesFromNode(ins.SelectStmt, tables)
		}
	}

	// UpdateStmt
	if upd := node.GetUpdateStmt(); upd != nil {
		if upd.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: upd.Relation}
			extractTablesFromNode(rv, tables)
		}
		for _, from := range upd.FromClause {
			extractTablesFromNode(from, tables)
		}
		if upd.WhereClause != nil {
			extractTablesFromNode(upd.WhereClause, tables)
		}
	}

	// DeleteStmt
	if del := node.GetDeleteStmt(); del != nil {
		if del.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: del.Relation}
			extractTablesFromNode(rv, tables)
		}
		if del.WhereClause != nil {
			extractTablesFromNode(del.WhereClause, tables)
		}
	}

	// DropStmt
	if drop := node.GetDropStmt(); drop != nil {
		for _, obj := range drop.Objects {
			if list := obj.GetList(); list != nil {
				var parts []string
				for _, item := range list.Items {
					if s := item.GetString_(); s != nil {
						parts = append(parts, strings.ToLower(s.Sval))
					}
				}
				if len(parts) > 0 {
					*tables = append(*tables, strings.Join(parts, "."))
				}
			}
		}
	}

	// TruncateStmt
	if trunc := node.GetTruncateStmt(); trunc != nil {
		for _, rel := range trunc.Relations {
			extractTablesFromNode(rel, tables)
		}
	}

	// JoinExpr
	if join := node.GetJoinExpr(); join != nil {
		extractTablesFromNode(join.Larg, tables)
		extractTablesFromNode(join.Rarg, tables)
	}

	// SubLink (subqueries in WHERE, etc.)
	if sub := node.GetSubLink(); sub != nil {
		extractTablesFromNode(sub.Subselect, tables)
	}

	// RangeSubselect (subquery in FROM)
	if rsub := node.GetRangeSubselect(); rsub != nil {
		extractTablesFromNode(rsub.Subquery, tables)
	}

	// FuncCall — check for table references in function args
	if fc := node.GetFuncCall(); fc != nil {
		for _, arg := range fc.Args {
			extractTablesFromNode(arg, tables)
		}
	}

	// ResTarget
	if rt := node.GetResTarget(); rt != nil {
		if rt.Val != nil {
			extractTablesFromNode(rt.Val, tables)
		}
	}

	// BoolExpr (AND/OR)
	if be := node.GetBoolExpr(); be != nil {
		for _, arg := range be.Args {
			extractTablesFromNode(arg, tables)
		}
	}

	// A_Expr (comparisons)
	if ae := node.GetAExpr(); ae != nil {
		if ae.Lexpr != nil {
			extractTablesFromNode(ae.Lexpr, tables)
		}
		if ae.Rexpr != nil {
			extractTablesFromNode(ae.Rexpr, tables)
		}
	}

	// CopyStmt
	if cp := node.GetCopyStmt(); cp != nil {
		if cp.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: cp.Relation}
			extractTablesFromNode(rv, tables)
		}
		if cp.Query != nil {
			extractTablesFromNode(cp.Query, tables)
		}
	}
}

// extractFunctionsFromNode recursively extracts all function calls from the AST
func extractFunctionsFromNode(node *pg_query.Node, functions *[]string) {
	if node == nil {
		return
	}

	// FuncCall node
	if fc := node.GetFuncCall(); fc != nil {
		var parts []string
		for _, nameNode := range fc.Funcname {
			if s := nameNode.GetString_(); s != nil {
				parts = append(parts, strings.ToLower(s.Sval))
			}
		}
		if len(parts) > 0 {
			// Store both schema-qualified and bare name
			fullName := strings.Join(parts, ".")
			*functions = append(*functions, fullName)
			// If schema-qualified, also add bare name for matching
			if len(parts) > 1 {
				*functions = append(*functions, parts[len(parts)-1])
			}
		}
		// Recurse into function arguments
		for _, arg := range fc.Args {
			extractFunctionsFromNode(arg, functions)
		}
	}

	// Recurse into all statement types
	if sel := node.GetSelectStmt(); sel != nil {
		for _, from := range sel.FromClause {
			extractFunctionsFromNode(from, functions)
		}
		for _, target := range sel.TargetList {
			extractFunctionsFromNode(target, functions)
		}
		if sel.WhereClause != nil {
			extractFunctionsFromNode(sel.WhereClause, functions)
		}
		if sel.WithClause != nil {
			for _, cte := range sel.WithClause.Ctes {
				if c := cte.GetCommonTableExpr(); c != nil {
					extractFunctionsFromNode(c.Ctequery, functions)
				}
			}
		}
		if sel.Larg != nil {
			larg := &pg_query.Node{}
			larg.Node = &pg_query.Node_SelectStmt{SelectStmt: sel.Larg}
			extractFunctionsFromNode(larg, functions)
		}
		if sel.Rarg != nil {
			rarg := &pg_query.Node{}
			rarg.Node = &pg_query.Node_SelectStmt{SelectStmt: sel.Rarg}
			extractFunctionsFromNode(rarg, functions)
		}
	}

	if ins := node.GetInsertStmt(); ins != nil {
		if ins.SelectStmt != nil {
			extractFunctionsFromNode(ins.SelectStmt, functions)
		}
	}

	if upd := node.GetUpdateStmt(); upd != nil {
		for _, target := range upd.TargetList {
			extractFunctionsFromNode(target, functions)
		}
		if upd.WhereClause != nil {
			extractFunctionsFromNode(upd.WhereClause, functions)
		}
		for _, from := range upd.FromClause {
			extractFunctionsFromNode(from, functions)
		}
	}

	if del := node.GetDeleteStmt(); del != nil {
		if del.WhereClause != nil {
			extractFunctionsFromNode(del.WhereClause, functions)
		}
	}

	// JoinExpr
	if join := node.GetJoinExpr(); join != nil {
		extractFunctionsFromNode(join.Larg, functions)
		extractFunctionsFromNode(join.Rarg, functions)
		if join.Quals != nil {
			extractFunctionsFromNode(join.Quals, functions)
		}
	}

	// SubLink
	if sub := node.GetSubLink(); sub != nil {
		extractFunctionsFromNode(sub.Subselect, functions)
	}

	// RangeSubselect
	if rsub := node.GetRangeSubselect(); rsub != nil {
		extractFunctionsFromNode(rsub.Subquery, functions)
	}

	// ResTarget
	if rt := node.GetResTarget(); rt != nil {
		if rt.Val != nil {
			extractFunctionsFromNode(rt.Val, functions)
		}
	}

	// BoolExpr
	if be := node.GetBoolExpr(); be != nil {
		for _, arg := range be.Args {
			extractFunctionsFromNode(arg, functions)
		}
	}

	// A_Expr
	if ae := node.GetAExpr(); ae != nil {
		if ae.Lexpr != nil {
			extractFunctionsFromNode(ae.Lexpr, functions)
		}
		if ae.Rexpr != nil {
			extractFunctionsFromNode(ae.Rexpr, functions)
		}
	}

	// CopyStmt
	if cp := node.GetCopyStmt(); cp != nil {
		if cp.Query != nil {
			extractFunctionsFromNode(cp.Query, functions)
		}
	}

	// RangeFunction (functions in FROM clause like dblink)
	if rf := node.GetRangeFunction(); rf != nil {
		for _, funcList := range rf.Functions {
			if list := funcList.GetList(); list != nil {
				for _, item := range list.Items {
					extractFunctionsFromNode(item, functions)
				}
			}
		}
	}
}

// stripLeadingSET removes leading SET statements to parse the actual query
func stripLeadingSET(query string) string {
	normalized := strings.TrimSpace(query)
	upper := strings.ToUpper(normalized)
	if strings.HasPrefix(upper, "SET ") {
		idx := strings.Index(normalized, ";")
		if idx >= 0 && idx+1 < len(normalized) {
			return strings.TrimSpace(normalized[idx+1:])
		}
	}
	return normalized
}

// dedup removes duplicate strings from a slice
func dedup(items []string) []string {
	seen := make(map[string]bool)
	var result []string
	for _, item := range items {
		if !seen[item] {
			seen[item] = true
			result = append(result, item)
		}
	}
	return result
}
