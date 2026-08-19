# VM Pulse

Self-hosted, AI-first control plane for your servers, VPS boxes and network equipment — from a
couple of hosts to a full homelab rack. Single Go binary (embedded Svelte SPA) + SQLite. No agents
to install, no inbound ports required for monitoring. Simple enough for a first-time VPS owner,
powerful enough for a homelabber.

> Status: **alpha.** Core planes are functional: monitoring, alerting, AI assistant (web +
> Telegram), SSH terminal, events journal, 2FA/vault. Releases are cross-compiled binaries;
> see `make build-windows` / the release pipeline notes in `.github/workflows/`.

## Install (Linux, from a release)

```bash
# 1) grab the binary for your arch from github.com/skibine/VMP/releases (example: amd64;
#    arm64 builds exist too)
V=$(curl -s https://api.github.com/repos/skibine/VMP/releases/latest | grep -oP '"tag_name":\s*"\K[^"]+')
curl -LO "https://github.com/skibine/VMP/releases/download/$V/vmpulse_${V#v}_linux_amd64.tar.gz"
tar xzf "vmpulse_${V#v}_linux_amd64.tar.gz" && cd "vmpulse_${V#v}_linux_amd64"

# 2) one-shot host posture check (read-only; also available as a button on the login page)
./vmpulse doctor

# 3) run; first start prints a generated admin password to the console
./vmpulse
```

Default UI: `http://127.0.0.1:8443` (local mode binds loopback only). Change the password
after the first login, then set up 2FA and Telegram alerts as you go.

To run it on a remote VPS the safe way, keep `mode: local` and use an SSH tunnel
(`ssh -L 8443:127.0.0.1:8443 user@vps` — the UI stays on your localhost, nothing exposed).
`mode: server` binds `0.0.0.0` for use behind a reverse proxy with TLS; run `vmpulse doctor`
first and read the two-plane notes below. Logs rotate in `logs/vmpulse.log` (10MB x3);
`log_file: "-"` in config.yaml disables the file sink.

## What it does

- **Fleet monitoring (Plane A, credential-free):** liveness + TCP/HTTP/ping/DNS checks with
  intervals, security-exposure scans, wide port scans, site info; servers *and* network
  equipment (routers, cameras, web panels — `kind: server | equipment`) *and* domains
  (whois/registration, TLS certificate expiry, DNS-change signature with acknowledge).
  Metrics (CPU/RAM/disk/net) collected over SSH when credentials are granted.
- **Alerting:** edge-triggered rules (DOWN/RECOVERED) with cooldowns, per-server delivery
  routing (Telegram / webhook / in-app bell), mutes, domain expiry reminders (repeat or
  one-shot). Every fired alert lands in the tamper-evident journal.
- **AI assistant (VMPilot):** the same agent in the web chat and in **Telegram** (long-poll
  bridge with ✅/❌ command-approval buttons; one shared conversation history). ~40 tools:
  everything the web UI can do — fleet/asset questions, ad-hoc probes, add VMs/domains/checks/
  rules/reminders, live command execution over SSH (destructive-pattern backstop + sudo support,
  approval flow by default, optional auto-approve). OpenAI-compatible providers: OpenAI, Z.AI
  (incl. Coding/China endpoints), DeepSeek, Groq, Mistral, OpenRouter, Ollama, LM Studio, vLLM.
- **Interactive management (Plane B, vault-gated):** SSH credentials stored encrypted (vault
  armed by master passphrase), web terminal, host-key pinning, live snapshots, journal errors,
  pending updates, virtual hosts.
- **Security & audit:** TOTP 2FA (required for storing credentials), tamper-evident `prev_hash`
  audit chain, events page with filters (direction: servers/domains/system, category, date,
  free text) and retention controls, `vmpulse doctor` host self-audit.

## Build & test

Go 1.26+ and Node 20+ (for the SPA).

```bash
make web            # build SPA into internal/web/dist (embedded by the Go binary)
go build ./...      # compile
go vet ./...        # static checks
go test ./... -v    # run tests (prints [IMP:7-10] Semantic Trace lines)
make all            # vet + test + build (with web)
make build-windows  # hardened windows/amd64 cross-compile into dist/
```

Anti-Loop runner (tracks failed attempts, prints a checklist on failure):

```bash
bash scripts/run_tests.sh
```

## Run

```bash
cp config.yaml.example config.yaml   # edit listen/mode as needed
go run ./cmd/vmpulse -config config.yaml
curl http://127.0.0.1:8443/healthz
./vmpulse doctor                     # optional: one-shot host self-audit (--json supported)
```

Default UI: `http://127.0.0.1:8443`. First run bootstraps the admin user from
`bootstrap_admin_password` in config.yaml (remove the field after the first start).
Database migrations apply automatically on start; a `.bak` snapshot is taken before each start.

## Layout

| Path | Role |
|---|---|
| `cmd/vmpulse/` | entry point (config → store → engine → api → tgchat), `doctor` subcommand |
| `internal/config/` | `config.yaml` loader, `local`/`server` modes |
| `internal/store/` | SQLite (pure-Go `modernc.org/sqlite`), WAL, embedded migrations (0001–0031) |
| `internal/monitor/` | check engine: tcp/http/ping/dns/dnsbl/whois/tls, port scans, exposures, site info, RDAP |
| `internal/alerts/` | rule evaluator (edge-triggered + cooldowns), delivery channels (telegram/webhook/in-app), domain reminders |
| `internal/ai/` | LLM agent: provider-agnostic client, tool registry (~40 tools), shared chat history |
| `internal/tgchat/` | Telegram bridge: long-poll, allowlist, ✅/❌ approve buttons |
| `internal/ssh/` | dialer, command executor (sudo-aware), inventory/updates/errors/vhosts readers |
| `internal/api/` | HTTP API + embedded SPA, web-SSH, audit viewer, notifications center |
| `internal/auth/` | sessions, TOTP 2FA, credential-vault gating |
| `internal/audit/` | tamper-evident `prev_hash` chain (Plane A + Plane B) |
| `internal/install/` | `vmpulse doctor` host self-audit (cross-platform collectors) |
| `web/` | Svelte SPA (fleet matrix, VM/domain detail, events, settings, chat) |

## Two-plane access model

- **Plane A (always-on monitoring):** external probes + agent metrics. Works **without** the
  master passphrase. Writes service events to the audit chain.
- **Plane B (interactive management):** web-SSH, AI command execution, credential storage.
  **Always gated** by the unlocked credential vault (master passphrase) and 2FA.

## Documentation for agents

- `AGENTS.md` — repo conventions for AI coding agents (semantic markup, LDD logging, testing).

## License

MIT — see [LICENSE](LICENSE). Free to use, modify and redistribute.
