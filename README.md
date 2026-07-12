# VM Pulse

Self-hosted, AI-first control plane for a small fleet of virtual machines (1–30).
Single Go binary + SQLite. Simple enough for a first-time VPS owner, powerful enough for a
homelabber. See `.kilo/plans/1781676816769-vmpulse-foundation-v2.md` for the design.

> Status: **Phase 0 bootstrap scaffold.** This slice establishes the project skeleton
> (config, SQLite store, tamper-evident audit, `/healthz`, structured LDD logging) and the
> Go adaptation of the semantic protocol. Monitoring checkers, the AI layer, web-SSH, and the
> Svelte frontend land in later slices.

## Build & test

Go 1.26+ required.

```bash
go build ./...      # compile
go vet ./...        # static checks
go test ./... -v    # run tests (prints [IMP:7-10] Semantic Trace lines)
```

Anti-Loop runner (tracks failed attempts, prints a checklist on failure):

```bash
bash scripts/run_tests.sh
```

## Run

```bash
cp config.yaml.example config.yaml   # then edit mode/listen as needed
go run ./cmd/vmpulse -config config.yaml
curl http://127.0.0.1:8443/healthz   # {"status":"ok","db":true,"schema_version":1}
```

## Layout

| Path | Role |
|---|---|
| `cmd/vmpulse/` | entry point (config → store → audit → api) |
| `internal/config/` | `config.yaml` loader, `local`/`server` modes |
| `internal/store/` | SQLite (pure-Go `modernc.org/sqlite`), WAL, embedded migrations |
| `internal/store/migrations/` | versioned SQL (`0001_init.sql`, …) embedded via `go:embed` |
| `internal/audit/` | tamper-evident `prev_hash` chain (Plane A + Plane B) |
| `internal/api/` | HTTP server + `/healthz`, graceful shutdown |
| `internal/logging/` | `slog` + LDD helper (`[IMP:N][Func][Block] msg`) |
| `internal/lddcheck/` | parses `[IMP:N]` for Semantic Trace Verification |
| `scripts/run_tests.sh` | Anti-Loop test runner |

## Two-plane access model

- **Plane A (always-on monitoring):** external probes + agent metrics. Works **without** the
  master passphrase. Writes service events to the audit chain.
- **Plane B (interactive management):** web-SSH, AI mutating actions, hardening. **Always
  gated** by the unlocked credential vault (master passphrase).

## Documentation for agents

- `AGENTS.md` — Go adaptation of the semantic protocol (regions, LDD, testing).
- `.kilo/plans/1781676816769-vmpulse-foundation-v2.md` — authoritative design (v2).
- `.kilo/plans/devplan-00-bootstrap-scaffold.md` — this slice's development plan.

## License

AGPLv3.
