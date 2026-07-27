// Package main is the VM Pulse single-binary entry point.
//
// region MODULE_CONTRACT [DOMAIN(8): Entry; CONCEPT(7): Bootstrap; TECH(8): main,signal]
// @purpose Wire config -> store -> audit -> api and run the instance until interrupted.
// @invariants
//   - On SIGINT/SIGTERM the process drains the HTTP server and closes the store.
//   - A service-start event is written to the audit chain (Plane A) before serving.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: main, entrypoint, bootstrap, signal, sigint, sigterm, wire, serve
// STRUCTURE: ▶ ┌flags┐ → ○ config.Load → ○ store.Open → ⊕ audit.Append(START) → ⚡ api.Serve ⟂ sig → ⎋ store.Close
package main

import (
	"context"
	"encoding/base64"
	"flag"
	"fmt"
	"log/slog"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/skibine/vm-pulse/internal/ai"
	"github.com/skibine/vm-pulse/internal/alerts"
	"github.com/skibine/vm-pulse/internal/api"
	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/auth"
	"github.com/skibine/vm-pulse/internal/config"
	"github.com/skibine/vm-pulse/internal/crypto"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/metrics"
	"github.com/skibine/vm-pulse/internal/monitor"
	"github.com/skibine/vm-pulse/internal/ssh"
	"github.com/skibine/vm-pulse/internal/store"
	"golang.org/x/term"
)

// region FUNC_main [DOMAIN(8): Entry; CONCEPT(7): Bootstrap; TECH(7): main]
// @purpose Orchestrate startup and shutdown of a VM Pulse instance.
// @complexity 5
// endregion FUNC_main
func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
	reset2FA := flag.String("reset-2fa", "", "BREAK-GLASS: disable 2FA for the given username and exit (run on the box if locked out)")
	askPass := flag.Bool("ask-passphrase", false, "prompt for the vault master passphrase at startup (hidden input) instead of reading it from config/env")
	flag.Parse()

	logger := logging.Setup(parseLevel("info"), os.Stdout)
	logging.LDD(logger, 9, "main", "START", "vmpulse starting")

	cfg, err := config.Load(*configPath, logger)
	if err != nil {
		logging.LDD(logger, 10, "main", "CONFIG_FAIL", err.Error())
		os.Exit(1)
	}
	// Re-apply configured log level for all subsequent output.
	logger = logging.Setup(parseLevel(cfg.LogLevel), os.Stdout)

	// Apply web-SSH hardening knobs (per-user session limit + idle reaper) before api.New wires the
	// routes. Zero values keep the built-in defaults (3 sessions, 30 min idle).
	api.SetWebSSHDefaults(cfg.Server.WebSSHSessionLimit, cfg.Server.WebSSHIdleMin)

	s, err := store.Open(cfg.DBPath, logger)
	if err != nil {
		logging.LDD(logger, 10, "main", "STORE_FAIL", err.Error())
		os.Exit(1)
	}
	defer func() {
		if cerr := s.Close(); cerr != nil {
			logging.LDD(logger, 9, "main", "CLOSE_FAIL", cerr.Error())
		}
	}()

	armVault(context.Background(), s, cfg, logger, *askPass)

	// BREAK-GLASS recovery: a user who lost their authenticator AND backup codes can be unblocked by
	// an operator with filesystem access: `vmpulse -config ... -reset-2fa <username>`. This disables
	// 2FA for that user and exits — the operator must then log in with the password and re-enroll.
	if *reset2FA != "" {
		u, err := s.GetUserByUsername(context.Background(), *reset2FA)
		if err != nil {
			logging.LDD(logger, 10, "reset-2fa", "USER_NOT_FOUND", *reset2FA)
			os.Exit(1)
		}
		if err := s.DisableTOTP(context.Background(), u.ID); err != nil {
			logging.LDD(logger, 10, "reset-2fa", "FAIL", err.Error())
			os.Exit(1)
		}
		_ = audit.Append(s.DB, logger, audit.Entry{
			Plane: audit.PlaneB, UserID: u.ID, Action: "auth.2fa_breakglass_reset",
			Detail: "username=" + *reset2FA, Success: true,
		})
		logging.LDD(logger, 9, "reset-2fa", "DONE", "2FA disabled for "+*reset2FA+" — log in with the password now")
		return
	}

	if err := audit.Append(s.DB, logger, audit.Entry{
		Plane:   audit.PlaneA,
		Action:  "service.start",
		Detail:  `{"mode":"` + cfg.Mode + `","listen":"` + cfg.Listen + `"}`,
		Success: true,
	}); err != nil {
		logging.LDD(logger, 10, "main", "AUDIT_FAIL", err.Error())
		os.Exit(1)
	}

	// First-run bootstrap: create the initial owner if no users exist and creds are configured.
	bootstrapAdmin(context.Background(), s, cfg, logger)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	// Plane A monitoring engine (always-on, no credential dependency).
	eng := monitor.New(s, monitor.DefaultRegistry(), logger, monitor.DefaultOptions())
	eng.Start(ctx)
	defer eng.Stop()

	// Ensure every VM has the always-on system liveness check (drives the fleet dot independently of
	// alert config) + the periodic system exposures check (auto security scan -> alert rules).
	// Backfills pre-existing VMs that predate the auto-provisioning.
	if vms, err := s.ListVMs(context.Background(), true); err == nil {
		for _, vm := range vms {
			_ = s.EnsureSystemLiveness(context.Background(), vm.ID, vm.PortSSH)
			_ = s.EnsureSystemExposures(context.Background(), vm.ID)
		}
	}
	// Same for domains: backfill the system whois (registration expiry) + tls (cert expiry) checks
	// so existing domains get expiry monitoring without re-adding them.
	if doms, err := s.ListDomains(context.Background()); err == nil {
		for _, d := range doms {
			_ = s.EnsureDomainChecks(context.Background(), d.ID)
		}
	}

	// Plane A alert evaluator (consumes results, fires alerts to channels).
	ev := alerts.New(s, alerts.DefaultRegistry(logger), logger, 30*time.Second)
	ev.Start(ctx)
	defer ev.Stop()

	server := api.New(s, cfg.Listen, logger)
	// Plane B: deny-by-default auth on /api/ (healthz + login stay public).
	server.Use(auth.Middleware(s, logger))

	// AI copilot: migrate config.AI into the settings store once (if present), then wire a
	// runtime SettingsProvider so AI is configurable from the Settings UI without restart.
	seedAI(ctx, s, cfg, logger)
	// AI executor wraps the SSH dialer so approved (or auto-approved) commands can run on VMs.
	sshDialer := ssh.New(s, logger)
	aiRegistry := ai.NewRegistry(append(ai.StoreTools(s), ai.ActionTools(s, &sshActionExec{dialer: sshDialer, st: s})...)...)
	server.WithAgent(&ai.Agent{Provider: &ai.SettingsProvider{Store: s}, Tools: aiRegistry, Logger: logger})

	// Plane A metrics pull-poller: periodically SSHes metrics-enabled VMs (reusing the vault) and
	// records CPU/RAM/disk/load samples; hourly downsampling (§5.2). Runs until ctx is cancelled.
	pollInterval := time.Duration(cfg.Metrics.PollIntervalSec) * time.Second
	if pollInterval <= 0 {
		pollInterval = 15 * time.Minute // default cadence: slow on purpose — SSH creds are touched each poll,
		// so we favor on-demand snapshots + a slow trend poll over frequent root-SSH dialing.
	}
	go metrics.New(s, sshDialer, logger).WithInterval(pollInterval).Run(ctx)

	// Daily SQLite backup (VACUUM INTO snapshot to <dbpath>.bak) — cheap insurance: the single
	// file holds config, metrics and the tamper-evident audit chain. Snapshots immediately on
	// startup, then every 24h; a corrupted/lost DB is recoverable from the last .bak.
	go backupLoop(ctx, s, cfg.DBPath, logger, 24*time.Hour)

	if err := server.Serve(ctx); err != nil {
		logging.LDD(logger, 10, "main", "SERVE_FAIL", err.Error())
		os.Exit(1)
	}

	_ = audit.Append(s.DB, logger, audit.Entry{
		Plane: audit.PlaneA, Action: "service.stop", Success: true,
	})
	logging.LDD(logger, 9, "main", "STOP", "vmpulse stopped")
}

// sshActionExec implements ai.ActionExecutor: runs an approved command on a VM over SSH.
type sshActionExec struct {
	dialer *ssh.Dialer
	st     *store.Store
}

func (e *sshActionExec) Execute(ctx context.Context, vmID int64, command string) (string, error) {
	client, _, derr := e.dialer.Dial(ctx, vmID)
	if derr != nil {
		return "", derr
	}
	defer client.Close()
	// Pass the stored sudo password so privileged commands run via `sudo -S` non-interactively.
	var sudoPassword string
	if creds, ok, _ := e.st.GetVMCredentials(ctx, vmID); ok {
		sudoPassword = creds.SudoPassword
	}
	rctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	return e.dialer.RunCommand(rctx, client, command, sudoPassword)
}

// region FUNC_parseLevel [DOMAIN(7): Config; CONCEPT(5): LogLevel; TECH(4): slog]
// @purpose Map a config string to an slog.Level (default Info).
// @complexity 2
// endregion FUNC_parseLevel
func parseLevel(s string) slog.Level {
	switch s {
	case "debug":
		return slog.LevelDebug
	case "warn":
		return slog.LevelWarn
	case "error":
		return slog.LevelError
	default:
		return slog.LevelInfo
	}
}

// region FUNC_bootstrapAdmin [DOMAIN(9): Security; CONCEPT(7): Bootstrap; TECH(6): store,argon2]
// @purpose Create the initial owner once, when no users exist. If no password is configured,
//
//	a strong random one is generated and printed ONCE to stdout (so a secret never needs to
//	live in config.yaml). A lingering bootstrap_admin_password after first run triggers a
//	per-startup warning to remove the stale credential from config.
//
// @complexity 4
// @invariants
//   - A generated password is printed only to stdout; it is never written to the structured log.
//   - If users already exist, no user is created regardless of configured creds.
//
// endregion FUNC_bootstrapAdmin
func bootstrapAdmin(ctx context.Context, s *store.Store, cfg *config.Config, logger *slog.Logger) {
	user := strings.TrimSpace(cfg.Auth.BootstrapAdminUsername)
	if user == "" {
		user = "admin"
	}
	configuredPass := cfg.Auth.BootstrapAdminPassword

	count, err := s.CountUsers(ctx)
	if err != nil {
		logging.LDD(logger, 9, "bootstrap", "COUNT_FAIL", err.Error())
		return
	}
	if count > 0 {
		// Users already exist: a leftover bootstrap password in config is a stale secret that
		// should not linger next to the DB. Warn every startup until the operator removes it.
		if strings.TrimSpace(configuredPass) != "" {
			logging.LDD(logger, 9, "bootstrap", "STALE_CREDS",
				"an admin user already exists but bootstrap_admin_password is still set in config.yaml — remove it")
		}
		return
	}

	// First run, no users. Prefer a generated password so no secret is stored in config at all.
	pass := strings.TrimSpace(configuredPass)
	generated := false
	if pass == "" {
		p, err := crypto.RandomPassword(24)
		if err != nil {
			logging.LDD(logger, 10, "bootstrap", "GEN_FAIL", err.Error())
			return
		}
		pass = p
		generated = true
	}
	hash, err := auth.HashPassword(pass)
	if err != nil {
		logging.LDD(logger, 10, "bootstrap", "HASH_FAIL", err.Error())
		return
	}
	if _, err := s.CreateUser(ctx, user, hash, "owner"); err != nil {
		logging.LDD(logger, 10, "bootstrap", "CREATE_FAIL", err.Error())
		return
	}
	if generated {
		// Printed to stdout (not the logger) so the secret lands in the console/journal once and
		// the operator captures it; the structured log only records that it was printed.
		fmt.Printf("\n=== VMPulse first-run bootstrap ===\n  username: %s\n  password: %s\n  >>> CHANGE THIS PASSWORD AFTER FIRST LOGIN <<<\n======================================\n\n", user, pass)
		logging.LDD(logger, 9, "bootstrap", "CREATED", "owner="+user+" generated password printed to stdout (change after first login)")
	} else {
		logging.LDD(logger, 9, "bootstrap", "CREATED", "owner="+user+" (password taken from config — remove bootstrap_admin_password from config.yaml now)")
	}
}

// region FUNC_backupLoop [DOMAIN(8): Storage; CONCEPT(7): Backup; TECH(7): goroutine,ticker]
// @purpose Snapshot the database to <dbpath>.bak immediately on startup and then every "every",
//
//	so the last good copy is always recoverable. VACUUM INTO refuses to overwrite, so the
//	previous .bak is removed before each snapshot. Returns when ctx is cancelled.
//
// @complexity 4
// endregion FUNC_backupLoop
func backupLoop(ctx context.Context, s *store.Store, dbPath string, logger *slog.Logger, every time.Duration) {
	dest := dbPath + ".bak"
	run := func() {
		_ = os.Remove(dest) // VACUUM INTO fails if the destination already exists.
		if err := s.Backup(ctx, dest); err != nil {
			logging.LDD(logger, 9, "backupLoop", "FAIL", err.Error())
			return
		}
		if info, err := os.Stat(dest); err == nil {
			logging.LDD(logger, 7, "backupLoop", "DONE", fmt.Sprintf("dest=%s size=%d", dest, info.Size()))
		}
	}
	run() // immediate first snapshot so a backup exists before the first 24h tick.
	t := time.NewTicker(every)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			run()
		case <-ctx.Done():
			return
		}
	}
}

// region FUNC_armVault [DOMAIN(9): Security; CONCEPT(7): AtRestKey; TECH(7): argon2id,config_meta]
// @purpose Derive the at-rest key from the master passphrase and a persisted salt; arm the store.
// @complexity 5
// @invariants
//   - The passphrase is NEVER persisted; only the random salt is (config_meta.vault_salt).
//   - Passphrase resolution: --ask-passphrase prompt > VMPULSE_VAULT_PASSPHRASE env > config.yaml
//     (config is a fallback and logs a warning — the recommended paths are the prompt or env var,
//     so the passphrase does not live next to the DB on disk).
//   - Empty passphrase -> vault disabled (plaintext secrets).
//
// endregion FUNC_armVault
func armVault(ctx context.Context, s *store.Store, cfg *config.Config, logger *slog.Logger, ask bool) {
	pass := resolvePassphrase(cfg, ask, logger)
	if strings.TrimSpace(pass) == "" {
		logging.LDD(logger, 7, "main", "VAULT_DISABLED", "set vault.passphrase (or VMPULSE_VAULT_PASSPHRASE / --ask-passphrase) to encrypt secrets")
		return
	}
	cfg.Vault.Passphrase = pass // so the rest of startup (e.g. cred decryption) uses the resolved value
	saltStr, ok, err := s.GetMeta(ctx, "vault_salt")
	var salt []byte
	if err != nil {
		logging.LDD(logger, 10, "main", "VAULT_SALT_READ_FAIL", err.Error())
		return
	}
	if ok {
		salt, _ = base64.StdEncoding.DecodeString(saltStr)
	} else {
		salt, err = crypto.GenerateSalt()
		if err != nil {
			logging.LDD(logger, 10, "main", "VAULT_SALT_GEN_FAIL", err.Error())
			return
		}
		_ = s.SetMeta(ctx, "vault_salt", base64.StdEncoding.EncodeToString(salt))
	}
	if len(salt) == 0 {
		logging.LDD(logger, 10, "main", "VAULT_SALT_EMPTY", "cannot arm vault without a salt")
		return
	}
	s.SetVault(crypto.NewVault(pass, salt))
	src := "env"
	switch {
	case ask:
		src = "prompt"
	case cfg.VaultFromFile:
		src = "file (" + strings.TrimSpace(cfg.Vault.PassphraseFile) + ")"
	case cfg.VaultFromConfig:
		src = "config.yaml (WARNING: prefer --ask-passphrase, VMPULSE_VAULT_PASSPHRASE, or vault.passphrase_file)"
	}
	logging.LDD(logger, 9, "main", "VAULT_ARMED", "at-rest encryption enabled (source="+src+")")
}

// resolvePassphrase picks the master passphrase. Priority:
// prompt (--ask-passphrase) > env (VMPULSE_VAULT_PASSPHRASE) > passphrase_file (0600 file; also
// how systemd LoadCredential exposes the credential) > config.yaml passphrase (lowest, WARNED).
// cfg.VaultFromConfig is set ONLY when the resolved passphrase came from config.yaml on disk.
func resolvePassphrase(cfg *config.Config, ask bool, logger *slog.Logger) string {
	if ask {
		fmt.Fprint(os.Stderr, "vault master passphrase: ")
		b, err := term.ReadPassword(int(os.Stdin.Fd()))
		fmt.Fprintln(os.Stderr)
		if err != nil {
			logging.LDD(logger, 10, "main", "VAULT_PROMPT_FAIL", err.Error())
			return ""
		}
		return string(b)
	}
	if env := os.Getenv("VMPULSE_VAULT_PASSPHRASE"); env != "" {
		return env
	}
	// Passphrase file: read once at startup (trimmed of trailing newline). Preferred over
	// config.yaml because the file can live at 0600 outside the repo / be injected by systemd
	// (LoadCredential= makes it appear under $CREDENTIALS_DIRECTORY).
	if path := strings.TrimSpace(cfg.Vault.PassphraseFile); path != "" {
		// Expand env (e.g. $CREDENTIALS_DIRECTORY) so systemd LoadCredential= works: the unit sets
		// LoadCredential=vault.pass:... and the file appears under $CREDENTIALS_DIRECTORY/vault.pass.
		path = os.ExpandEnv(path)
		b, err := os.ReadFile(path)
		if err != nil {
			logging.LDD(logger, 10, "main", "VAULT_FILE_READ_FAIL", path+": "+err.Error())
			return ""
		}
		cfg.VaultFromFile = true
		return strings.TrimSpace(string(b))
	}
	cfg.VaultFromConfig = cfg.Vault.Configured()
	return cfg.Vault.Passphrase
}

// region FUNC_seedAI [DOMAIN(9): AI; CONCEPT(7): Migration; TECH(6): store]
// @purpose On first run, migrate ai.* from config into the settings store (key encrypted).
//
//	After that the settings store is the source of truth (managed via Settings UI).
//
// @complexity 3
// endregion FUNC_seedAI
func seedAI(ctx context.Context, s *store.Store, cfg *config.Config, logger *slog.Logger) {
	has, err := s.HasSetting(ctx, store.SettingAIAPIKey)
	if err != nil {
		logging.LDD(logger, 9, "main", "AI_SEED_CHECK_FAIL", err.Error())
		return
	}
	if has {
		return // already managed via Settings
	}
	if !cfg.AI.Configured() {
		logging.LDD(logger, 7, "main", "AI_NOT_SET", "configure AI in Settings (or ai.* in config)")
		return
	}
	if err := s.SetAIConfig(ctx, store.AIConfig{APIURL: cfg.AI.APIURL, APIKey: cfg.AI.APIKey, Model: cfg.AI.Model}); err != nil {
		logging.LDD(logger, 10, "main", "AI_SEED_FAIL", err.Error())
		return
	}
	logging.LDD(logger, 9, "main", "AI_SEEDED", "migrated ai.* from config to settings store")
}
