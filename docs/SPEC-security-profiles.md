# FaultWall Security Profiles + Full Parser Coverage

## Problem

1. `extractOperationFromNode()` handles 18 of 115 pg_query_go statement types. The other 97 return "UNKNOWN" and are default-denied — breaking legitimate SQL for users.
2. Users must manually list `blocked_operations` per agent — tedious and error-prone.
3. No way to opt into allowing UNKNOWN operations.

## Solution

Two changes: (A) full parser coverage so UNKNOWN is rare, (B) security profiles so users pick a posture instead of listing operations.

---

## Part A: Full Parser Coverage

### Operation Categories

Map ALL 115 statement types into 8 categories. The parser returns the **category** as the operation string (not individual statement names), so the policy engine works with a small predictable set.

| Category | Operation String | Statement Types |
|----------|-----------------|-----------------|
| **DML** (Data Manipulation) | `SELECT`, `INSERT`, `UPDATE`, `DELETE`, `MERGE`, `COPY` | GetSelectStmt, GetInsertStmt, GetUpdateStmt, GetDeleteStmt, GetMergeStmt, GetCopyStmt |
| **DDL** (Data Definition) | `CREATE`, `ALTER`, `DROP`, `TRUNCATE` | GetCreateStmt, GetCreateTableAsStmt, GetCreateSchemaStmt, GetCreateSeqStmt, GetCreateStatsStmt, GetCreateDomainStmt, GetCreateEnumStmt, GetCreateRangeStmt, GetCompositeTypeStmt, GetCreateAmStmt, GetCreateCastStmt, GetCreateConversionStmt, GetCreateOpClassStmt, GetCreateOpFamilyStmt, GetCreateTransformStmt, GetDefineStmt, GetIndexStmt, GetRuleStmt, GetCreateTrigStmt, GetViewStmt, GetCreateForeignTableStmt, GetAlterTableStmt, GetAlterDomainStmt, GetAlterEnumStmt, GetAlterSeqStmt, GetAlterStatsStmt, GetAlterCollationStmt, GetAlterTypeStmt, GetAlterOpFamilyStmt, GetAlterOperatorStmt, GetAlterObjectSchemaStmt, GetAlterObjectDependsStmt, GetAlterOwnerStmt, GetAlterTableSpaceOptionsStmt, GetAlterTableMoveAllStmt, GetAlterTsconfigurationStmt, GetAlterTsdictionaryStmt, GetRenameStmt, GetDropStmt, GetTruncateStmt, GetCommentStmt, GetSecLabelStmt, GetReplicaIdentityStmt |
| **DCL** (Access Control) | `GRANT`, `REVOKE`, `ALTER_ROLE`, `CREATE_ROLE`, `DROP_ROLE` | GetGrantStmt, GetGrantRoleStmt, GetAlterDefaultPrivilegesStmt, GetAlterRoleStmt, GetAlterRoleSetStmt, GetCreateRoleStmt, GetDropRoleStmt, GetReassignOwnedStmt, GetDropOwnedStmt, GetAlterUserMappingStmt, GetCreateUserMappingStmt, GetDropUserMappingStmt, GetCreatePolicyStmt, GetAlterPolicyStmt |
| **TCL** (Transaction) | `TRANSACTION` | GetTransactionStmt, GetConstraintsSetStmt |
| **FUNCTION** (Code Execution) | `CREATE_FUNCTION`, `CALL`, `DO` | GetCreateFunctionStmt, GetAlterFunctionStmt, GetCreatePlangStmt, GetCallStmt, GetDoStmt, GetCreateEventTrigStmt, GetAlterEventTrigStmt |
| **SESSION** (Session/Config) | `SET`, `SHOW`, `DISCARD`, `PREPARE`, `EXECUTE`, `DEALLOCATE`, `LISTEN`, `NOTIFY`, `LOCK`, `FETCH`, `CLOSE_CURSOR`, `DECLARE_CURSOR` | GetVariableSetStmt, GetVariableShowStmt, GetDiscardStmt, GetPrepareStmt, GetExecuteStmt, GetDeallocateStmt, GetListenStmt, GetUnlistenStmt, GetNotifyStmt, GetLockStmt, GetFetchStmt, GetClosePortalStmt, GetDeclareCursorStmt, GetLoadStmt, GetPlassignStmt, GetReturnStmt |
| **ADMIN** (Server Admin) | `VACUUM`, `REINDEX`, `CLUSTER`, `CHECKPOINT`, `ALTER_SYSTEM`, `ALTER_DATABASE`, `REFRESH_MATVIEW`, `CREATE_TABLESPACE`, `DROP_TABLESPACE`, `CREATE_DATABASE`, `DROP_DATABASE` | GetVacuumStmt, GetReindexStmt, GetClusterStmt, GetCheckPointStmt, GetAlterSystemStmt, GetAlterDatabaseStmt, GetAlterDatabaseSetStmt, GetAlterDatabaseRefreshCollStmt, GetRefreshMatViewStmt, GetCreateTableSpaceStmt, GetDropTableSpaceStmt, GetCreatedbStmt, GetDropdbStmt |
| **EXTENSION** (Extensions/FDW) | `CREATE_EXTENSION`, `ALTER_EXTENSION`, `CREATE_FDW`, `IMPORT_FOREIGN_SCHEMA`, `CREATE_PUBLICATION`, `CREATE_SUBSCRIPTION` | GetCreateExtensionStmt, GetAlterExtensionStmt, GetAlterExtensionContentsStmt, GetCreateFdwStmt, GetAlterFdwStmt, GetCreateForeignServerStmt, GetAlterForeignServerStmt, GetImportForeignSchemaStmt, GetCreatePublicationStmt, GetAlterPublicationStmt, GetCreateSubscriptionStmt, GetAlterSubscriptionStmt, GetDropSubscriptionStmt |
| **EXPLAIN** | `EXPLAIN` | GetExplainStmt |

### Implementation in parser.go

Replace the current `extractOperationFromNode()` switch with a complete mapping. Every single `Get*Stmt()` method gets a case. Return the **specific operation string** (e.g. `VACUUM`, `CREATE_FUNCTION`, `ALTER_SYSTEM`) — the profiles map categories to these strings.

Add a new exported map for profile lookups:

```go
// OperationCategory maps each specific operation to its security category
var OperationCategory = map[string]string{
    "SELECT": "DML", "INSERT": "DML", "UPDATE": "DML",
    "DELETE": "DML", "MERGE": "DML", "COPY": "DML",
    "CREATE": "DDL", "ALTER": "DDL", "DROP": "DDL", "TRUNCATE": "DDL",
    // ... full map
    "VACUUM": "ADMIN", "REINDEX": "ADMIN", "CHECKPOINT": "ADMIN",
    // etc.
}
```

**UNKNOWN should now only happen for genuinely unparseable SQL** (syntax errors that even pg_query can't handle). With 115 types mapped, this should be near-zero in practice.

---

## Part B: Security Profiles

### Profile Definitions

Three built-in profiles. Defined as Go constants (not YAML — they're product defaults).

#### `permissive` — Log everything, block nothing
- **Blocked categories:** none
- **Blocked operations:** none  
- **Use case:** "I just want visibility into what my agents are doing"
- Every query is allowed but fully logged with agent attribution

#### `standard` — Block dangerous ops, allow normal work
- **Blocked categories:** DCL, ADMIN, EXTENSION, FUNCTION
- **Blocked operations within DML:** COPY
- **Allowed:** SELECT, INSERT, UPDATE, DELETE, MERGE, EXPLAIN, all SESSION, TRANSACTION
- **Conditions:** "DELETE must include WHERE", "UPDATE must include WHERE"
- **Use case:** "My agents need to read and write data, but shouldn't touch schema, roles, or server config"

#### `strict` — Allowlist only
- **Allowed operations:** SELECT, INSERT, UPDATE, DELETE, EXPLAIN, TRANSACTION
- **Everything else:** blocked
- **Conditions:** "DELETE must include WHERE", "UPDATE must include WHERE"
- **Use case:** "Agents get basic CRUD and nothing else"

### YAML Schema Changes

```yaml
# NEW: top-level profiles section (optional — built-ins always available)
profiles:
  custom-readonly:
    extends: strict
    allowed_operations:
      - SELECT
      - EXPLAIN
    # Overrides strict's allowed list — only SELECT and EXPLAIN

agents:
  cursor-ai:
    description: "Cursor IDE agent"
    auth_token: "cursor-secret-123"
    profile: standard              # <-- NEW: pick a profile
    # profile_overrides:           # <-- NEW: optional per-agent tweaks
    #   allow:
    #     - COPY                   # allow COPY even though standard blocks it
    #   block:
    #     - DELETE                 # block DELETE even though standard allows it
    missions:
      summarize-feedback:
        tables:
          - "public.feedback"
        max_rows: 1000
    # blocked_operations is STILL supported for backward compat
    # If both profile and blocked_operations exist, profile wins
    blocked_tables:
      - public.users
```

### Profile Resolution Logic (in policy.go)

```
1. Does agent have `profile`? → Load that profile's blocked/allowed ops
2. Does agent have `profile_overrides`? → Apply allow/block overrides on top
3. Does agent have legacy `blocked_operations`? → Use those (backward compat, no profile)
4. Neither? → Allow all operations (fully permissive, original behavior)
```

### Backward Compatibility

- Existing `blocked_operations` YAML still works unchanged
- If an agent has no `profile` field, behavior is identical to current
- Adding `profile` replaces `blocked_operations` for that agent
- Both can coexist in the same file (different agents)

---

## Part C: Default-Deny for UNKNOWN

**Remove the current hard block on UNKNOWN.** Replace with profile-aware behavior:
- `permissive`: allow + log
- `standard`: block (safe default for unrecognized)
- `strict`: block

Since Part A maps all 115 types, UNKNOWN will only fire for garbage SQL — blocking it is fine in standard/strict. In permissive, even garbage gets through (user's choice).

---

## Files to Change

1. **parser.go** — Expand `extractOperationFromNode()` to cover all 115 types. Add `OperationCategory` map. More specific return values (e.g. `VACUUM` not just `ADMIN`).
2. **parser_test.go** — Add test cases for representative statements from each category (at least 1 per category, focus on the dangerous ones).
3. **policy.go** — Add `SecurityProfile` struct, built-in profiles, profile resolution in `CheckQuery()`, backward compat with `blocked_operations`.
4. **policies.yaml** — Update example config to use profiles. Keep backward-compat examples.
5. **README.md** — Document profiles in the configuration section.

## Tests Required

- Parser: at least one test per category (ADMIN: VACUUM, EXTENSION: CREATE EXTENSION, FUNCTION: DO block, SESSION: SET, etc.)
- Policy: test each profile blocks/allows correctly
- Policy: test profile_overrides (allow override, block override)
- Policy: test backward compat (agent with blocked_operations, no profile)
- Policy: test UNKNOWN handling per profile
- Policy: test custom profile extending built-in

## Non-Goals (explicitly out of scope)

- No changes to proxy.go, identity.go, or the wire protocol
- No changes to MCP tools
- No new dependencies
- No breaking changes to existing policies.yaml format
