# Test Guide — Phase 0 Bootstrap Scaffold

Bridges the Coder output to an independent QA tester. Read alongside
`the bootstrap development plan (see the project history)`.

## Scope under test

The scaffold proves the architecture spine: config loading, SQLite store + migrations,
tamper-evident audit chain, `/healthz`, and structured LDD logging. No business logic
(monitoring/AI/SSH) exists yet.

## How to run

```bash
go test ./... -v                 # native
bash scripts/run_tests.sh        # Anti-Loop runner (attempt counter + checklist)
```

Packages: `internal/{logging,config,store,audit,api,lddcheck}`. `cmd/vmpulse` has no test
files yet (its logic is covered transitively by `api`/`store`/`audit`).

## Verification queries (SQL)

After any test run you can open the DB it created and check:

```sql
-- 1. Migrations applied (expect >= 1):
SELECT MAX(version) FROM schema_versions;

-- 2. Audit chain row count + plane distribution:
SELECT plane, count(*) FROM audit_log GROUP BY plane;

-- 3. Chain integrity (re-run programmatically via audit.VerifyChain):
SELECT id, action, plane, success, substr(hash,1,8) FROM audit_log ORDER BY id;
```

## Expected `[IMP:9-10]` Semantic Trace markers

These MUST appear in the log trajectory (Anti-Illusion: green tests without them is a failure):

| Marker | Where | Meaning |
|---|---|---|
| `[IMP:9][Append][APPENDED]` | `audit_test.go` (chain test) | an audit record was chained |
| `[IMP:7][healthHandler][PROBE]` | `api_test.go` | `/healthz` was exercised |
| `[IMP:8][migrate][APPLIED]` / `[DONE]` | `store_test.go` | migrations applied once |
| `[IMP:8][Open][READY]` | `store_test.go` | DB handle usable |

## Pass criteria

- `go test ./...` exits 0 (100% PASS).
- `go vet ./...` clean.
- `go build ./...` clean.
- Audit tamper test (`TestChain_DetectsTampering`) fails `VerifyChain` after an `UPDATE` —
  i.e. tampering is detected (not silently accepted).
- Every `*.go` source file contains `// region`, `@purpose`, `GREP_SUMMARY:`, `STRUCTURE:`.
