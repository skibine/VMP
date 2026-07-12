#!/usr/bin/env bash
# region RUN_TESTS_SH [DOMAIN(7): Testing; CONCEPT(9): AntiLoop; TECH(7): bash]
# @purpose Anti-Loop runner for VM Pulse (Go adaptation of the pytest conftest counter).
#          Wraps `go test ./...`, tracks failed attempts in tests/.test_counter.json,
#          prints an attempt-aware CHECKLIST on failure, and RESETS the counter to 0 on
#          a full 100% PASS.
# @invariants
#   - The counter file lives at tests/.test_counter.json (gitignored).
#   - On 100% PASS the counter is ALWAYS reset to 0 and exit code is 0.
# @usage: bash scripts/run_tests.sh
# endregion RUN_TESTS_SH
# GREP_SUMMARY: anti-loop, test runner, counter, checklist, go test, attempts
# STRUCTURE: ▶ ┌counter┐ → ○ go test → 〈pass? reset:inc+CHECKLIST〉 → ⎋ exit

set -u
ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
COUNTER_FILE="$ROOT/tests/.test_counter.json"
mkdir -p "$ROOT/tests"

# Read current attempt count (default 0).
attempts=0
if [[ -f "$COUNTER_FILE" ]]; then
    attempts=$(grep -o '"attempts":[0-9]*' "$COUNTER_FILE" | grep -o '[0-9]*' || true)
fi
[[ -z "$attempts" ]] && attempts=0

echo "=== VM Pulse test runner (attempt #$((attempts+1))) ==="
if (cd "$ROOT" && go test ./... -v); then
    # 100% PASS -> reset.
    printf '{"attempts":0}\n' > "$COUNTER_FILE"
    echo "SUCCESS: All tests passed, semantic log verification available via IMP:7-10 (t.Log)."
    exit 0
fi

# Failure -> increment and emit attempt-aware guidance.
attempts=$((attempts+1))
printf '{"attempts":%s}\n' "$attempts" > "$COUNTER_FILE"
echo
echo "=== TEST FAILURE (attempt #$attempts) ==="
case "$attempts" in
    1|2)
        echo "CHECKLIST (common VM Pulse Go failures):"
        echo "  [1] SQL comment syntax: SQL files MUST use '--' or /* */, NEVER '//' (SQLite syntax error 'near /')."
        echo "  [2] go:embed paths resolve relative to the .go file; migrations live in internal/store/migrations/."
        echo "  [3] schema_versions must be bootstrapped (CREATE IF NOT EXISTS) BEFORE isApplied() queries it."
        echo "  [4] audit.Append must receive a non-nil logger if a test asserts [IMP:9] (Semantic Trace)."
        echo "  [5] SetMaxOpenConns(1) for SQLite to avoid 'database is locked'."
        echo "  [6] Tests use t.TempDir() — never hardcode DB paths (Zero Hardcode)."
        ;;
    3)
        echo "External help: consult upstream docs (modernc.org/sqlite, database/sql) or use MCP Context7."
        ;;
    4)
        echo "WARNING: Looping risk! Pause and reflect. Are you repeating a failed strategy? Try Superposition."
        ;;
    *)
        echo "CRITICAL ERROR: Agent looping detected. STOP. Formulate a help request for an operator."
        ;;
esac
exit 1
