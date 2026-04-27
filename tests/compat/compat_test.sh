#!/bin/bash
# FaultWall Compatibility Test Harness
# Usage: ./compat_test.sh <target_name> <host> <port> <db> <user> <password> [extra_psql_args]
#
# Outputs structured pass/fail results with raw evidence per test

set -u
TARGET="${1:?usage: target_name host port db user pass [extra]}"
HOST="${2}"
PORT="${3}"
DB="${4}"
USER="${5}"
PASS="${6}"
EXTRA="${7:-}"

PSQL=/opt/homebrew/opt/postgresql@16/bin/psql
OUT=/tmp/compat-${TARGET}.log
echo "==== FaultWall Compatibility: $TARGET ====" > $OUT
echo "Target: $HOST:$PORT / $DB as $USER" >> $OUT
echo "Extra psql args: $EXTRA" >> $OUT
echo "Started: $(date -u +%FT%TZ)" >> $OUT
echo "" >> $OUT

PASS_COUNT=0
FAIL_COUNT=0

run_test() {
    local name="$1"
    local expected="$2"  # "pass" or "fail" (fail = query should be blocked)
    local sql="$3"
    local identity="$4"  # optional agent identity

    echo "---- TEST: $name (expect=$expected) ----" >> $OUT
    echo "SQL: $sql" >> $OUT
    [ -n "$identity" ] && echo "Identity: $identity" >> $OUT

    local output
    local exitcode
    if [ -n "$identity" ]; then
        output=$(PGPASSWORD="$PASS" PGAPPNAME="$identity" $PSQL -h "$HOST" -p "$PORT" -U "$USER" -d "$DB" $EXTRA -c "$sql" 2>&1)
    else
        output=$(PGPASSWORD="$PASS" $PSQL -h "$HOST" -p "$PORT" -U "$USER" -d "$DB" $EXTRA -c "$sql" 2>&1)
    fi
    exitcode=$?

    echo "Exit: $exitcode" >> $OUT
    echo "Output:" >> $OUT
    echo "$output" | head -20 >> $OUT
    echo "" >> $OUT

    # Verdict logic
    local verdict="?"
    if [ "$expected" = "pass" ]; then
        if [ $exitcode -eq 0 ]; then verdict="PASS"; PASS_COUNT=$((PASS_COUNT+1))
        else verdict="FAIL"; FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    elif [ "$expected" = "fail" ]; then
        # For "fail" we expect FaultWall to block — either non-zero exit OR error about policy
        if [ $exitcode -ne 0 ] || echo "$output" | grep -qiE "policy|blocked|denied|faultwall"; then
            verdict="PASS (correctly blocked)"; PASS_COUNT=$((PASS_COUNT+1))
        else
            verdict="FAIL (should have been blocked!)"; FAIL_COUNT=$((FAIL_COUNT+1))
        fi
    fi
    echo "VERDICT: $verdict" >> $OUT
    echo "" >> $OUT
    printf "%-50s %s\n" "$name" "$verdict"
}

# ========== Phase 1: Basic connectivity ==========
run_test "01. basic_select_1" "pass" "SELECT 1;" ""
run_test "02. version_query" "pass" "SELECT version();" ""
run_test "03. current_user" "pass" "SELECT current_user, current_database();" ""

# ========== Phase 2: Read queries on allowed tables ==========
run_test "04. select_feedback" "pass" "SELECT COUNT(*) FROM feedback;" "agent:testagent:mission:read:token:test-secret-abc123"
run_test "05. select_feedback_with_where" "pass" "SELECT id, body FROM feedback WHERE id > 0;" "agent:testagent:mission:read:token:test-secret-abc123"

# ========== Phase 3: Write queries ==========
run_test "06. insert_feedback" "pass" "INSERT INTO feedback(user_id, body) VALUES (99, 'compat test');" "agent:testagent:mission:write:token:test-secret-abc123"
run_test "07. update_feedback_with_where" "pass" "UPDATE feedback SET body='updated' WHERE user_id=99;" "agent:testagent:mission:write:token:test-secret-abc123"
run_test "08. delete_feedback_with_where" "pass" "DELETE FROM feedback WHERE user_id=99;" "agent:testagent:mission:write:token:test-secret-abc123"

# ========== Phase 4: Policy enforcement (blocked tables) ==========
run_test "09. blocked_table_users" "fail" "SELECT COUNT(*) FROM users;" "agent:testagent:mission:attack:token:test-secret-abc123"
run_test "10. blocked_table_payments" "fail" "SELECT COUNT(*) FROM payments;" "agent:testagent:mission:attack:token:test-secret-abc123"

# ========== Phase 5: Policy enforcement (blocked functions) ==========
run_test "11. blocked_pg_sleep" "fail" "SELECT pg_sleep(0.1);" "agent:testagent:mission:attack:token:test-secret-abc123"

# ========== Phase 6: Policy enforcement (strict profile) ==========
run_test "12. strict_allows_select" "pass" "SELECT 1;" "agent:readonly-agent:mission:read:token:readonly-xyz789"
run_test "13. strict_blocks_ddl" "fail" "CREATE TABLE tmp_test(id int);" "agent:readonly-agent:mission:attack:token:readonly-xyz789"

# ========== Phase 7: Prepared statements ==========
run_test "14. prepare_execute" "pass" "PREPARE s1(int) AS SELECT id FROM feedback WHERE id=\$1; EXECUTE s1(1); DEALLOCATE s1;" ""

# ========== Phase 8: Transactions ==========
run_test "15. transaction_commit" "pass" "BEGIN; SELECT 1; COMMIT;" ""
run_test "16. transaction_rollback" "pass" "BEGIN; SELECT 1; ROLLBACK;" ""

# ========== Phase 9: Multi-statement ==========
run_test "17. multi_stmt_allowed" "pass" "SELECT 1; SELECT 2;" ""

# ========== Phase 10: Session state ==========
run_test "18. set_work_mem" "pass" "SET work_mem = '64MB'; SHOW work_mem;" ""
run_test "19. temp_table" "pass" "CREATE TEMP TABLE tmp(id int); INSERT INTO tmp VALUES (1); SELECT COUNT(*) FROM tmp;" ""

# ========== Phase 11: pg driver specifics ==========
run_test "20. empty_query" "pass" ";" ""
run_test "21. schema_qualified" "pass" "SELECT COUNT(*) FROM public.feedback;" ""

# ========== Phase 12: SSL negotiation (psql auto-detects) ==========
# psql with sslmode=prefer tries SSL then falls back — already covered by basic connectivity
# Explicit sslmode=require test (will be added via EXTRA param for Supabase/RDS)

echo "" >> $OUT
echo "===========" >> $OUT
echo "SUMMARY: $PASS_COUNT passed, $FAIL_COUNT failed" >> $OUT
echo "===========" >> $OUT

echo ""
echo "==========================================="
echo "$TARGET: $PASS_COUNT passed, $FAIL_COUNT failed"
echo "Full log: $OUT"
echo "==========================================="

exit $FAIL_COUNT
