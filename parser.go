package main

import (
	"log"
	"strings"

	pg_query "github.com/pganalyze/pg_query_go/v6"
)

// ParsedQuery holds AST-extracted information about a SQL query
type ParsedQuery struct {
	Operation      string   // first statement's operation (backward compat)
	Operations     []string // all operations found (multi-statement support)
	Tables         []string
	Functions      []string
	HasRegprocCast bool // true if query contains ::regproc/::regprocedure cast
	UsedAST        bool
}

// sanitizeQuery strips null bytes, zero-width characters, and other Unicode tricks
func sanitizeQuery(query string) string {
	// Strip null bytes
	query = strings.ReplaceAll(query, "\x00", "")
	// Strip zero-width characters
	for _, r := range []string{"\u200B", "\u200C", "\u200D", "\uFEFF", "\u00A0"} {
		query = strings.ReplaceAll(query, r, "")
	}
	return strings.TrimSpace(query)
}

// ParseQuery parses a SQL query using pg_query_go AST parser.
// Falls back to regex-based parsing if AST parsing fails.
func ParseQuery(query string) *ParsedQuery {
	query = sanitizeQuery(query)
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
	for _, rawStmt := range tree.Stmts {
		stmt := rawStmt.GetStmt()
		if stmt == nil {
			continue
		}
		op := extractOperationFromNode(stmt)
		pq.Operations = append(pq.Operations, op)

		// EXPLAIN ANALYZE actually executes the inner query — extract its
		// operation so the policy engine can block dangerous inner statements.
		if expl := stmt.GetExplainStmt(); expl != nil && expl.Query != nil {
			for _, optNode := range expl.Options {
				if dv := optNode.GetDefElem(); dv != nil {
					if strings.EqualFold(dv.Defname, "analyze") {
						innerOp := extractOperationFromNode(expl.Query)
						if innerOp != "" && innerOp != "UNKNOWN" {
							pq.Operations = append(pq.Operations, innerOp)
						}
						break
					}
				}
			}
		}

		// CREATE RULE can piggyback additional statements (DO ALSO / INSTEAD).
		// Extract inner operations so the policy engine can block them.
		if rule := stmt.GetRuleStmt(); rule != nil {
			for _, action := range rule.Actions {
				innerOp := extractOperationFromNode(action)
				if innerOp != "" && innerOp != "UNKNOWN" {
					pq.Operations = append(pq.Operations, innerOp)
				}
			}
		}

		extractTablesFromNode(stmt, &pq.Tables)
		extractFunctionsFromNode(stmt, &pq.Functions)

		// Detect dangerous type casts (regproc, regprocedure, regclass)
		if !pq.HasRegprocCast {
			pq.HasRegprocCast = hasRegprocCast(stmt)
		}
	}

	// First operation for backward compat
	if len(pq.Operations) > 0 {
		pq.Operation = pq.Operations[0]
	}

	// Deduplicate tables and functions
	pq.Tables = dedup(pq.Tables)
	pq.Functions = dedup(pq.Functions)

	return pq
}

// OperationCategory maps each specific operation string to its security category.
// Used by security profiles to resolve category-level blocking.
var OperationCategory = map[string]string{
	// DML
	"SELECT": "DML", "INSERT": "DML", "UPDATE": "DML",
	"DELETE": "DML", "MERGE": "DML", "COPY": "DML",
	// DDL
	"CREATE": "DDL", "ALTER": "DDL", "DROP": "DDL", "TRUNCATE": "DDL",
	// DCL
	"GRANT": "DCL", "REVOKE": "DCL", "SET_ROLE": "DCL", "ALTER_ROLE": "DCL", "CREATE_ROLE": "DCL",
	"DROP_ROLE": "DCL", "REASSIGN_OWNED": "DCL", "DROP_OWNED": "DCL",
	"CREATE_POLICY": "DCL", "ALTER_POLICY": "DCL",
	"CREATE_USER_MAPPING": "DCL", "ALTER_USER_MAPPING": "DCL", "DROP_USER_MAPPING": "DCL",
	"ALTER_DEFAULT_PRIVILEGES": "DCL",
	// TCL
	"TRANSACTION": "TCL",
	// FUNCTION
	"CREATE_FUNCTION": "FUNCTION", "ALTER_FUNCTION": "FUNCTION",
	"CREATE_PLANG": "FUNCTION", "CALL": "FUNCTION", "DO": "FUNCTION",
	"CREATE_EVENT_TRIGGER": "FUNCTION", "ALTER_EVENT_TRIGGER": "FUNCTION",
	// SESSION
	"SET": "SESSION", "SHOW": "SESSION", "DISCARD": "SESSION",
	"PREPARE": "SESSION", "EXECUTE": "SESSION", "DEALLOCATE": "SESSION",
	"LISTEN": "SESSION", "UNLISTEN": "SESSION", "NOTIFY": "SESSION",
	"LOCK": "SESSION", "FETCH": "SESSION", "CLOSE_CURSOR": "SESSION",
	"DECLARE_CURSOR": "SESSION", "LOAD": "ADMIN",
	"PLASSIGN": "SESSION", "RETURN": "SESSION",
	// ADMIN
	"VACUUM": "ADMIN", "REINDEX": "ADMIN", "CLUSTER": "ADMIN",
	"CHECKPOINT": "ADMIN", "ALTER_SYSTEM": "ADMIN",
	"ALTER_DATABASE": "ADMIN", "ALTER_DATABASE_SET": "ADMIN",
	"ALTER_DATABASE_REFRESH_COLL": "ADMIN",
	"REFRESH_MATVIEW": "ADMIN",
	"CREATE_TABLESPACE": "ADMIN", "DROP_TABLESPACE": "ADMIN",
	"CREATE_DATABASE": "ADMIN", "DROP_DATABASE": "ADMIN",
	// EXTENSION
	"CREATE_EXTENSION": "EXTENSION", "ALTER_EXTENSION": "EXTENSION",
	"ALTER_EXTENSION_CONTENTS": "EXTENSION",
	"CREATE_FDW": "EXTENSION", "ALTER_FDW": "EXTENSION",
	"CREATE_FOREIGN_SERVER": "EXTENSION", "ALTER_FOREIGN_SERVER": "EXTENSION",
	"IMPORT_FOREIGN_SCHEMA": "EXTENSION",
	"CREATE_PUBLICATION": "EXTENSION", "ALTER_PUBLICATION": "EXTENSION",
	"CREATE_SUBSCRIPTION": "EXTENSION", "ALTER_SUBSCRIPTION": "EXTENSION",
	"DROP_SUBSCRIPTION": "EXTENSION",
	// EXPLAIN
	"EXPLAIN": "EXPLAIN",
}

// extractOperationFromNode determines the SQL operation type from an AST node.
// Returns specific operation strings that map to categories via OperationCategory.
func extractOperationFromNode(node *pg_query.Node) string {
	switch {
	// ── DML ──
	case node.GetSelectStmt() != nil:
		return "SELECT"
	case node.GetInsertStmt() != nil:
		return "INSERT"
	case node.GetUpdateStmt() != nil:
		return "UPDATE"
	case node.GetDeleteStmt() != nil:
		return "DELETE"
	case node.GetMergeStmt() != nil:
		return "MERGE"
	case node.GetCopyStmt() != nil:
		return "COPY"

	// ── DDL ──
	case node.GetCreateStmt() != nil:
		return "CREATE"
	case node.GetCreateTableAsStmt() != nil:
		return "CREATE"
	case node.GetCreateSchemaStmt() != nil:
		return "CREATE"
	case node.GetCreateSeqStmt() != nil:
		return "CREATE"
	case node.GetCreateStatsStmt() != nil:
		return "CREATE"
	case node.GetCreateDomainStmt() != nil:
		return "CREATE"
	case node.GetCreateEnumStmt() != nil:
		return "CREATE"
	case node.GetCreateRangeStmt() != nil:
		return "CREATE"
	case node.GetCompositeTypeStmt() != nil:
		return "CREATE"
	case node.GetCreateAmStmt() != nil:
		return "CREATE"
	case node.GetCreateCastStmt() != nil:
		return "CREATE"
	case node.GetCreateConversionStmt() != nil:
		return "CREATE"
	case node.GetCreateOpClassStmt() != nil:
		return "CREATE"
	case node.GetCreateOpFamilyStmt() != nil:
		return "CREATE"
	case node.GetCreateTransformStmt() != nil:
		return "CREATE"
	case node.GetDefineStmt() != nil:
		return "CREATE"
	case node.GetIndexStmt() != nil:
		return "CREATE"
	case node.GetRuleStmt() != nil:
		return "CREATE"
	case node.GetCreateTrigStmt() != nil:
		return "CREATE"
	case node.GetViewStmt() != nil:
		return "CREATE"
	case node.GetCreateForeignTableStmt() != nil:
		return "CREATE"
	case node.GetAlterTableStmt() != nil:
		return "ALTER"
	case node.GetAlterDomainStmt() != nil:
		return "ALTER"
	case node.GetAlterEnumStmt() != nil:
		return "ALTER"
	case node.GetAlterSeqStmt() != nil:
		return "ALTER"
	case node.GetAlterStatsStmt() != nil:
		return "ALTER"
	case node.GetAlterCollationStmt() != nil:
		return "ALTER"
	case node.GetAlterTypeStmt() != nil:
		return "ALTER"
	case node.GetAlterOpFamilyStmt() != nil:
		return "ALTER"
	case node.GetAlterOperatorStmt() != nil:
		return "ALTER"
	case node.GetAlterObjectSchemaStmt() != nil:
		return "ALTER"
	case node.GetAlterObjectDependsStmt() != nil:
		return "ALTER"
	case node.GetAlterOwnerStmt() != nil:
		return "ALTER"
	case node.GetAlterTableSpaceOptionsStmt() != nil:
		return "ALTER"
	case node.GetAlterTableMoveAllStmt() != nil:
		return "ALTER"
	case node.GetAlterTsconfigurationStmt() != nil:
		return "ALTER"
	case node.GetAlterTsdictionaryStmt() != nil:
		return "ALTER"
	case node.GetRenameStmt() != nil:
		return "ALTER"
	case node.GetDropStmt() != nil:
		return "DROP"
	case node.GetTruncateStmt() != nil:
		return "TRUNCATE"
	case node.GetCommentStmt() != nil:
		return "ALTER"
	case node.GetSecLabelStmt() != nil:
		return "ALTER"
	case node.GetReplicaIdentityStmt() != nil:
		return "ALTER"

	// ── DCL (Access Control) ──
	case node.GetGrantStmt() != nil:
		return "GRANT"
	case node.GetGrantRoleStmt() != nil:
		return "GRANT"
	case node.GetAlterDefaultPrivilegesStmt() != nil:
		return "ALTER_DEFAULT_PRIVILEGES"
	case node.GetAlterRoleStmt() != nil:
		return "ALTER_ROLE"
	case node.GetAlterRoleSetStmt() != nil:
		return "ALTER_ROLE"
	case node.GetCreateRoleStmt() != nil:
		return "CREATE_ROLE"
	case node.GetDropRoleStmt() != nil:
		return "DROP_ROLE"
	case node.GetReassignOwnedStmt() != nil:
		return "REASSIGN_OWNED"
	case node.GetDropOwnedStmt() != nil:
		return "DROP_OWNED"
	case node.GetAlterUserMappingStmt() != nil:
		return "ALTER_USER_MAPPING"
	case node.GetCreateUserMappingStmt() != nil:
		return "CREATE_USER_MAPPING"
	case node.GetDropUserMappingStmt() != nil:
		return "DROP_USER_MAPPING"
	case node.GetCreatePolicyStmt() != nil:
		return "CREATE_POLICY"
	case node.GetAlterPolicyStmt() != nil:
		return "ALTER_POLICY"

	// ── TCL (Transaction) ──
	case node.GetTransactionStmt() != nil:
		return "TRANSACTION"
	case node.GetConstraintsSetStmt() != nil:
		return "TRANSACTION"

	// ── FUNCTION (Code Execution) ──
	case node.GetCreateFunctionStmt() != nil:
		return "CREATE_FUNCTION"
	case node.GetAlterFunctionStmt() != nil:
		return "ALTER_FUNCTION"
	case node.GetCreatePlangStmt() != nil:
		return "CREATE_PLANG"
	case node.GetCallStmt() != nil:
		return "CALL"
	case node.GetDoStmt() != nil:
		return "DO"
	case node.GetCreateEventTrigStmt() != nil:
		return "CREATE_EVENT_TRIGGER"
	case node.GetAlterEventTrigStmt() != nil:
		return "ALTER_EVENT_TRIGGER"

	// ── SESSION ──
	case node.GetVariableSetStmt() != nil:
		vs := node.GetVariableSetStmt()
		nameLower := strings.ToLower(vs.Name)
		if nameLower == "role" || nameLower == "session_authorization" {
			return "SET_ROLE"
		}
		return "SET"
	case node.GetVariableShowStmt() != nil:
		return "SHOW"
	case node.GetDiscardStmt() != nil:
		return "DISCARD"
	case node.GetPrepareStmt() != nil:
		return "PREPARE"
	case node.GetExecuteStmt() != nil:
		return "EXECUTE"
	case node.GetDeallocateStmt() != nil:
		return "DEALLOCATE"
	case node.GetListenStmt() != nil:
		return "LISTEN"
	case node.GetUnlistenStmt() != nil:
		return "UNLISTEN"
	case node.GetNotifyStmt() != nil:
		return "NOTIFY"
	case node.GetLockStmt() != nil:
		return "LOCK"
	case node.GetFetchStmt() != nil:
		return "FETCH"
	case node.GetClosePortalStmt() != nil:
		return "CLOSE_CURSOR"
	case node.GetDeclareCursorStmt() != nil:
		return "DECLARE_CURSOR"
	case node.GetLoadStmt() != nil:
		return "LOAD"
	case node.GetPlassignStmt() != nil:
		return "PLASSIGN"
	case node.GetReturnStmt() != nil:
		return "RETURN"

	// ── ADMIN (Server Administration) ──
	case node.GetVacuumStmt() != nil:
		return "VACUUM"
	case node.GetReindexStmt() != nil:
		return "REINDEX"
	case node.GetClusterStmt() != nil:
		return "CLUSTER"
	case node.GetCheckPointStmt() != nil:
		return "CHECKPOINT"
	case node.GetAlterSystemStmt() != nil:
		return "ALTER_SYSTEM"
	case node.GetAlterDatabaseStmt() != nil:
		return "ALTER_DATABASE"
	case node.GetAlterDatabaseSetStmt() != nil:
		return "ALTER_DATABASE_SET"
	case node.GetAlterDatabaseRefreshCollStmt() != nil:
		return "ALTER_DATABASE_REFRESH_COLL"
	case node.GetRefreshMatViewStmt() != nil:
		return "REFRESH_MATVIEW"
	case node.GetCreateTableSpaceStmt() != nil:
		return "CREATE_TABLESPACE"
	case node.GetDropTableSpaceStmt() != nil:
		return "DROP_TABLESPACE"
	case node.GetCreatedbStmt() != nil:
		return "CREATE_DATABASE"
	case node.GetDropdbStmt() != nil:
		return "DROP_DATABASE"

	// ── EXTENSION (Extensions / FDW / Replication) ──
	case node.GetCreateExtensionStmt() != nil:
		return "CREATE_EXTENSION"
	case node.GetAlterExtensionStmt() != nil:
		return "ALTER_EXTENSION"
	case node.GetAlterExtensionContentsStmt() != nil:
		return "ALTER_EXTENSION_CONTENTS"
	case node.GetCreateFdwStmt() != nil:
		return "CREATE_FDW"
	case node.GetAlterFdwStmt() != nil:
		return "ALTER_FDW"
	case node.GetCreateForeignServerStmt() != nil:
		return "CREATE_FOREIGN_SERVER"
	case node.GetAlterForeignServerStmt() != nil:
		return "ALTER_FOREIGN_SERVER"
	case node.GetImportForeignSchemaStmt() != nil:
		return "IMPORT_FOREIGN_SCHEMA"
	case node.GetCreatePublicationStmt() != nil:
		return "CREATE_PUBLICATION"
	case node.GetAlterPublicationStmt() != nil:
		return "ALTER_PUBLICATION"
	case node.GetCreateSubscriptionStmt() != nil:
		return "CREATE_SUBSCRIPTION"
	case node.GetAlterSubscriptionStmt() != nil:
		return "ALTER_SUBSCRIPTION"
	case node.GetDropSubscriptionStmt() != nil:
		return "DROP_SUBSCRIPTION"

	// ── EXPLAIN ──
	case node.GetExplainStmt() != nil:
		return "EXPLAIN"

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
		// VALUES lists can contain subqueries and function calls
		for _, valRow := range sel.ValuesLists {
			if list := valRow.GetList(); list != nil {
				for _, item := range list.Items {
					extractTablesFromNode(item, tables)
				}
			}
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

	// RangeFunction (functions in FROM clause like unnest, dblink, generate_series)
	if rf := node.GetRangeFunction(); rf != nil {
		for _, funcList := range rf.Functions {
			if list := funcList.GetList(); list != nil {
				for _, item := range list.Items {
					extractTablesFromNode(item, tables)
				}
			}
		}
	}

	// A_Indirection — array subscript (expr)[n], field access expr.field
	if ai := node.GetAIndirection(); ai != nil {
		if ai.Arg != nil {
			extractTablesFromNode(ai.Arg, tables)
		}
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

	// PrepareStmt — recurse into the inner query body
	if prep := node.GetPrepareStmt(); prep != nil {
		if prep.Query != nil {
			extractTablesFromNode(prep.Query, tables)
		}
	}

	// CreateTableAsStmt (CTAS) — recurse into the SELECT subquery
	if ctas := node.GetCreateTableAsStmt(); ctas != nil {
		if ctas.Query != nil {
			extractTablesFromNode(ctas.Query, tables)
		}
	}

	// ExplainStmt — recurse into the inner query
	if expl := node.GetExplainStmt(); expl != nil {
		if expl.Query != nil {
			extractTablesFromNode(expl.Query, tables)
		}
	}

	// DeclareCursorStmt — recurse into the cursor query
	if dcur := node.GetDeclareCursorStmt(); dcur != nil {
		if dcur.Query != nil {
			extractTablesFromNode(dcur.Query, tables)
		}
	}

	// TypeCast — recurse into the inner expression (catches casted function calls)
	if tc := node.GetTypeCast(); tc != nil {
		if tc.Arg != nil {
			extractTablesFromNode(tc.Arg, tables)
		}
	}

	// CaseExpr — recurse into CASE branches (catches subqueries in CASE WHEN)
	if ce := node.GetCaseExpr(); ce != nil {
		if ce.Arg != nil {
			extractTablesFromNode(ce.Arg, tables)
		}
		for _, arg := range ce.Args {
			extractTablesFromNode(arg, tables)
		}
		if ce.Defresult != nil {
			extractTablesFromNode(ce.Defresult, tables)
		}
	}

	// CaseWhen — recurse into WHEN expr and result
	if cw := node.GetCaseWhen(); cw != nil {
		if cw.Expr != nil {
			extractTablesFromNode(cw.Expr, tables)
		}
		if cw.Result != nil {
			extractTablesFromNode(cw.Result, tables)
		}
	}

	// RuleStmt — recurse into rule actions (DO ALSO / INSTEAD can contain full statements)
	if rule := node.GetRuleStmt(); rule != nil {
		if rule.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: rule.Relation}
			extractTablesFromNode(rv, tables)
		}
		if rule.WhereClause != nil {
			extractTablesFromNode(rule.WhereClause, tables)
		}
		for _, action := range rule.Actions {
			extractTablesFromNode(action, tables)
		}
	}

	// AlterTableStmt — recurse into commands (column defaults can contain subqueries)
	if alt := node.GetAlterTableStmt(); alt != nil {
		if alt.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: alt.Relation}
			extractTablesFromNode(rv, tables)
		}
		for _, cmd := range alt.Cmds {
			extractTablesFromNode(cmd, tables)
		}
	}

	// AlterTableCmd — recurse into Def (ColumnDef with default expressions)
	if atc := node.GetAlterTableCmd(); atc != nil {
		if atc.Def != nil {
			extractTablesFromNode(atc.Def, tables)
		}
	}

	// ColumnDef — recurse into RawDefault and constraints (DEFAULT expressions)
	if cd := node.GetColumnDef(); cd != nil {
		if cd.RawDefault != nil {
			extractTablesFromNode(cd.RawDefault, tables)
		}
		for _, constraint := range cd.Constraints {
			if c := constraint.GetConstraint(); c != nil && c.RawExpr != nil {
				extractTablesFromNode(c.RawExpr, tables)
			}
		}
	}

	// CreateTrigStmt — extract trigger's target table
	if trig := node.GetCreateTrigStmt(); trig != nil {
		if trig.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: trig.Relation}
			extractTablesFromNode(rv, tables)
		}
		// Recurse into WHEN clause
		if trig.WhenClause != nil {
			extractTablesFromNode(trig.WhenClause, tables)
		}
	}

	// ViewStmt — recurse into the view's query
	if vs := node.GetViewStmt(); vs != nil {
		if vs.View != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: vs.View}
			extractTablesFromNode(rv, tables)
		}
		if vs.Query != nil {
			extractTablesFromNode(vs.Query, tables)
		}
	}

	// IndexStmt — recurse into WHERE predicate and index expressions
	if idx := node.GetIndexStmt(); idx != nil {
		if idx.Relation != nil {
			rv := &pg_query.Node{}
			rv.Node = &pg_query.Node_RangeVar{RangeVar: idx.Relation}
			extractTablesFromNode(rv, tables)
		}
		if idx.WhereClause != nil {
			extractTablesFromNode(idx.WhereClause, tables)
		}
		for _, param := range idx.IndexParams {
			extractTablesFromNode(param, tables)
		}
	}

	// IndexElem — recurse into expression (catches subqueries in expression indexes)
	if ie := node.GetIndexElem(); ie != nil {
		if ie.Expr != nil {
			extractTablesFromNode(ie.Expr, tables)
		}
	}

	// XmlExpr — recurse into args and named_args (catches subqueries in xmlelement etc)
	if xe := node.GetXmlExpr(); xe != nil {
		for _, arg := range xe.Args {
			extractTablesFromNode(arg, tables)
		}
		for _, arg := range xe.NamedArgs {
			extractTablesFromNode(arg, tables)
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
		// VALUES lists can contain function calls
		for _, valRow := range sel.ValuesLists {
			if list := valRow.GetList(); list != nil {
				for _, item := range list.Items {
					extractFunctionsFromNode(item, functions)
				}
			}
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

	// A_Indirection — array subscript (expr)[n], field access expr.field
	if ai := node.GetAIndirection(); ai != nil {
		if ai.Arg != nil {
			extractFunctionsFromNode(ai.Arg, functions)
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

	// PrepareStmt — recurse into the inner query body
	if prep := node.GetPrepareStmt(); prep != nil {
		if prep.Query != nil {
			extractFunctionsFromNode(prep.Query, functions)
		}
	}

	// CreateTableAsStmt (CTAS) — recurse into the SELECT subquery
	if ctas := node.GetCreateTableAsStmt(); ctas != nil {
		if ctas.Query != nil {
			extractFunctionsFromNode(ctas.Query, functions)
		}
	}

	// ExplainStmt — recurse into the inner query
	if expl := node.GetExplainStmt(); expl != nil {
		if expl.Query != nil {
			extractFunctionsFromNode(expl.Query, functions)
		}
	}

	// DeclareCursorStmt — recurse into the cursor query
	if dcur := node.GetDeclareCursorStmt(); dcur != nil {
		if dcur.Query != nil {
			extractFunctionsFromNode(dcur.Query, functions)
		}
	}

	// TypeCast — recurse into the inner expression (catches casted function calls)
	if tc := node.GetTypeCast(); tc != nil {
		// Check if casting to regproc/regprocedure — this invokes the function
		if tc.TypeName != nil {
			for _, n := range tc.TypeName.Names {
				if s := n.GetString_(); s != nil {
					name := strings.ToLower(s.Sval)
					if name == "regproc" || name == "regprocedure" || name == "regclass" || name == "regtype" {
						// The string constant IS the function/type name being referenced
						if tc.Arg != nil {
							if aconst := tc.Arg.GetAConst(); aconst != nil {
								if sval := aconst.GetSval(); sval != nil {
									fnName := strings.ToLower(sval.Sval)
									// Strip schema prefix if present
									if idx := strings.LastIndex(fnName, "."); idx >= 0 {
										*functions = append(*functions, fnName)
										*functions = append(*functions, fnName[idx+1:])
									} else {
										*functions = append(*functions, fnName)
									}
								}
							}
						}
					}
				}
			}
		}
		// Recurse (existing)
		if tc.Arg != nil {
			extractFunctionsFromNode(tc.Arg, functions)
		}
	}

	// CaseExpr — recurse into CASE branches
	if ce := node.GetCaseExpr(); ce != nil {
		if ce.Arg != nil {
			extractFunctionsFromNode(ce.Arg, functions)
		}
		for _, arg := range ce.Args {
			extractFunctionsFromNode(arg, functions)
		}
		if ce.Defresult != nil {
			extractFunctionsFromNode(ce.Defresult, functions)
		}
	}

	// CaseWhen — recurse into WHEN expr and result
	if cw := node.GetCaseWhen(); cw != nil {
		if cw.Expr != nil {
			extractFunctionsFromNode(cw.Expr, functions)
		}
		if cw.Result != nil {
			extractFunctionsFromNode(cw.Result, functions)
		}
	}

	// RuleStmt — recurse into rule actions
	if rule := node.GetRuleStmt(); rule != nil {
		if rule.WhereClause != nil {
			extractFunctionsFromNode(rule.WhereClause, functions)
		}
		for _, action := range rule.Actions {
			extractFunctionsFromNode(action, functions)
		}
	}

	// AlterTableStmt — recurse into commands
	if alt := node.GetAlterTableStmt(); alt != nil {
		for _, cmd := range alt.Cmds {
			extractFunctionsFromNode(cmd, functions)
		}
	}

	// AlterTableCmd — recurse into Def
	if atc := node.GetAlterTableCmd(); atc != nil {
		if atc.Def != nil {
			extractFunctionsFromNode(atc.Def, functions)
		}
	}

	// ColumnDef — recurse into RawDefault and constraints
	if cd := node.GetColumnDef(); cd != nil {
		if cd.RawDefault != nil {
			extractFunctionsFromNode(cd.RawDefault, functions)
		}
		for _, constraint := range cd.Constraints {
			if c := constraint.GetConstraint(); c != nil && c.RawExpr != nil {
				extractFunctionsFromNode(c.RawExpr, functions)
			}
		}
	}

	// CreateTrigStmt — extract trigger function name
	if trig := node.GetCreateTrigStmt(); trig != nil {
		var parts []string
		for _, nameNode := range trig.Funcname {
			if s := nameNode.GetString_(); s != nil {
				parts = append(parts, strings.ToLower(s.Sval))
			}
		}
		if len(parts) > 0 {
			fullName := strings.Join(parts, ".")
			*functions = append(*functions, fullName)
			if len(parts) > 1 {
				*functions = append(*functions, parts[len(parts)-1])
			}
		}
		// Recurse into WHEN clause
		if trig.WhenClause != nil {
			extractFunctionsFromNode(trig.WhenClause, functions)
		}
	}

	// ViewStmt — recurse into the view's query
	if vs := node.GetViewStmt(); vs != nil {
		if vs.Query != nil {
			extractFunctionsFromNode(vs.Query, functions)
		}
	}

	// IndexStmt — recurse into WHERE predicate and index expressions
	if idx := node.GetIndexStmt(); idx != nil {
		if idx.WhereClause != nil {
			extractFunctionsFromNode(idx.WhereClause, functions)
		}
		for _, param := range idx.IndexParams {
			extractFunctionsFromNode(param, functions)
		}
	}

	// IndexElem — recurse into expression
	if ie := node.GetIndexElem(); ie != nil {
		if ie.Expr != nil {
			extractFunctionsFromNode(ie.Expr, functions)
		}
	}

	// XmlExpr — recurse into args and named_args
	if xe := node.GetXmlExpr(); xe != nil {
		for _, arg := range xe.Args {
			extractFunctionsFromNode(arg, functions)
		}
		for _, arg := range xe.NamedArgs {
			extractFunctionsFromNode(arg, functions)
		}
	}
}

// dangerousTypeNames are type names that allow function/table OID resolution
// from string values, enabling blocklist bypasses.
var dangerousTypeNames = map[string]bool{
	"regproc":      true,
	"regprocedure": true,
	"regclass":     true,
	"regtype":      true,
	"regoper":      true,
	"regoperator":  true,
}

// hasRegprocCast recursively checks if the AST contains a TypeCast to a
// dangerous OID-resolving type (regproc, regprocedure, regclass, etc.).
func hasRegprocCast(node *pg_query.Node) bool {
	if node == nil {
		return false
	}

	if tc := node.GetTypeCast(); tc != nil {
		if tc.TypeName != nil {
			for _, nameNode := range tc.TypeName.Names {
				if s := nameNode.GetString_(); s != nil {
					if dangerousTypeNames[strings.ToLower(s.Sval)] {
						return true
					}
				}
			}
		}
		if tc.Arg != nil && hasRegprocCast(tc.Arg) {
			return true
		}
	}

	// Recurse into common node types
	if sel := node.GetSelectStmt(); sel != nil {
		for _, target := range sel.TargetList {
			if hasRegprocCast(target) {
				return true
			}
		}
		if sel.WhereClause != nil && hasRegprocCast(sel.WhereClause) {
			return true
		}
		for _, from := range sel.FromClause {
			if hasRegprocCast(from) {
				return true
			}
		}
	}
	if rt := node.GetResTarget(); rt != nil {
		if rt.Val != nil && hasRegprocCast(rt.Val) {
			return true
		}
	}
	if fc := node.GetFuncCall(); fc != nil {
		for _, arg := range fc.Args {
			if hasRegprocCast(arg) {
				return true
			}
		}
	}
	if sub := node.GetSubLink(); sub != nil {
		if hasRegprocCast(sub.Subselect) {
			return true
		}
	}
	if be := node.GetBoolExpr(); be != nil {
		for _, arg := range be.Args {
			if hasRegprocCast(arg) {
				return true
			}
		}
	}
	if ae := node.GetAExpr(); ae != nil {
		if hasRegprocCast(ae.Lexpr) || hasRegprocCast(ae.Rexpr) {
			return true
		}
	}
	if ce := node.GetCaseExpr(); ce != nil {
		for _, arg := range ce.Args {
			if hasRegprocCast(arg) {
				return true
			}
		}
		if ce.Defresult != nil && hasRegprocCast(ce.Defresult) {
			return true
		}
	}
	if cw := node.GetCaseWhen(); cw != nil {
		if hasRegprocCast(cw.Expr) || hasRegprocCast(cw.Result) {
			return true
		}
	}
	if nt := node.GetNullTest(); nt != nil {
		if nt.Arg != nil && hasRegprocCast(nt.Arg) {
			return true
		}
	}
	if xe := node.GetXmlExpr(); xe != nil {
		for _, arg := range xe.Args {
			if hasRegprocCast(arg) {
				return true
			}
		}
	}
	if prep := node.GetPrepareStmt(); prep != nil {
		if hasRegprocCast(prep.Query) {
			return true
		}
	}
	if ai := node.GetAIndirection(); ai != nil {
		if ai.Arg != nil && hasRegprocCast(ai.Arg) {
			return true
		}
	}
	if rule := node.GetRuleStmt(); rule != nil {
		for _, action := range rule.Actions {
			if hasRegprocCast(action) {
				return true
			}
		}
	}

	return false
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
