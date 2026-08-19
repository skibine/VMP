# AGENTS.md — VM Pulse (Go adaptation of the semantic protocol)

This project uses a structured agent workflow **adapted for Go + Svelte + SQLite**.
Any agent working in this repo MUST respect the conventions below.

## Project facts

- **Language:** Go 1.26+ (backend), Svelte (frontend, later), SQLite (storage).
- **Module path:** `github.com/skibine/vmp`.
- **SQLite driver:** `modernc.org/sqlite` (pure Go, no CGO) — chosen so GoReleaser
  cross-compiles cleanly (Win/Linux/macOS × x64/arm64). Do NOT switch to CGO drivers
  without revisiting the cross-compile pipeline.
- **Build/test entry:** `go build ./...`, `go test ./...`, `go vet ./...`.
- Design docs live in the private development archive (not part of the public repo).

## Lint / typecheck / test commands

Run before declaring a task done:

```bash
go build ./...
go vet ./...
go test ./... -v
```

If a future test runner script exists, prefer it (see Anti-Loop below).

## Semantic markup adaptation for Go

The protocol's Python tokens are adapted to Go idiom. The **searchable tokens are preserved**
(`region`, `@purpose`, `GREP_SUMMARY`, `STRUCTURE`, `[IMP:N]`), so grep-based navigation still works.

| Element | Python rule | Go adaptation |
|---|---|---|
| Region tags | `# region NAME [KW]` / `# endregion NAME` | `// region NAME [DOMAIN(X):..; CONCEPT(Y):..; TECH(Z):..]` / `// endregion NAME` |
| Function contract | `## @purpose` (Doxygen) | `// @purpose`, `// @io`, `// @complexity`, `// @uses`, `// @invariants` as Go doc-comment lines |
| Module contract | `# region MODULE_CONTRACT ... def _module_contract(): pass` | `// region MODULE_CONTRACT [...]` block + a package-level doc comment; the dummy function is **not** used in Go (Go documents packages, not dummy funcs). |
| Grep summary | `# GREP_SUMMARY:` | `// GREP_SUMMARY:` (keep literal token) |
| Flow diagram | `# STRUCTURE:` | `// STRUCTURE: ▶ ...` (keep literal token, one line) |
| LDD logging | `logger.info(f"[IMP:9]...")` | Use `internal/logging.LDD(logger, imp, fn, block, msg)` helper. Emits `[IMP:N][Func][Block] msg`. |

### Minimal Go module skeleton

```go
// Package store persists VM Pulse state in SQLite.
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): Persistence; TECH(9): SQLite,WAL]
// @purpose Provide the single source of truth (config/metrics/incidents/audit) via SQLite.
// @io dbPath string -> *Store
// @invariants
//   - Open always returns a WAL-mode database with migrations applied.
//   - schema_versions is authoritative for migration state.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: SQLite, WAL, migrations, schema_versions, store, persistence, bootstrap
// STRUCTURE: ▶ ┌dbPath┐ → ○ open → ⚡ PRAGMA WAL → ⊕ embed migrations → ∑ apply → ⎷ *Store
package store
```

### LDD helper usage

```go
import "github.com/skibine/vmp/internal/logging"
logging.LDD(logger, 9, "Open", "MIGRATED", "applied N migrations")
// emits: level=<warn> msg="[IMP:9][Open][MIGRATED] applied N migrations" imp=9
```

IMP→level mapping: 1-3 Debug, 4-8 Info, 9-10 Warn (so AI-belief logs surface).

## Testing (Go, not pytest)

- Tests are **co-located** (`foo_test.go`), idiomatic Go — NOT a root `tests/` folder.
- Use `t.TempDir()` for all DB files (Zero Hardcode rule equivalent).
- Tests MUST print `[IMP:7-10]` lines to stdout (Semantic Trace Verification) — capture the
  logger buffer or read stdout and grep `[IMP:`.
- **Anti-Loop Protocol:** `scripts/run_tests.sh` wraps `go test`, tracks attempts in
  `tests/.test_counter.json`, prints CHECKLIST on failure, resets to 0 on 100% PASS.
  Prefer it: `bash scripts/run_tests.sh`.
- FORBIDDEN: shelling out to the built binary to test business logic — call functions directly
  (httptest for HTTP).

## Directory layout

```
cmd/vmpulse/        entry point (main)
internal/
  logging/          slog + LDD helper
  config/           config.yaml loader, modes (local/server)
  store/            SQLite open + embedded migrations (SQL lives in store/migrations/ for go:embed)
  audit/            tamper-evident prev_hash chain
  api/              HTTP server + /healthz
  monitor/          (later) checkers/dispatcher/worker pool — Plane A
  alerts/           (later) rules/channels
  ssh/              (later) web-SSH engine — Plane B
  ai/               (later) MCP tools, LLM router
scripts/            run_tests.sh (Anti-Loop), etc.
web/                Svelte frontend (later slice)
```

## Two-plane access model (DO NOT break)

- **Plane A (always-on monitoring):** external probes + agent metrics. MUST work without the
  master passphrase. Agent has its own low-priv token; SSH creds are NOT used here.
- **Plane B (interactive mgmt):** web-SSH, AI mutating actions, hardening, quick actions.
  ALWAYS gated by the unlocked credential vault (master passphrase).
- Consequence for code: never make Plane A depend on `audit.Append`-of-credentials or on vault
  state. Plane A writes metric/check rows + its own service events.

## Conventions

- No emojis in code unless requested.
- No hardcoded secrets/default passwords anywhere — all generated at install.
- Keep `GREP_SUMMARY` / `STRUCTURE` on ONE line each.
