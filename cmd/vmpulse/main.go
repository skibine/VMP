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
)

// region FUNC_main [DOMAIN(8): Entry; CONCEPT(7): Bootstrap; TECH(7): main]
// @purpose Orchestrate startup and shutdown of a VM Pulse instance.
// @complexity 5
// endregion FUNC_main
func main() {
	configPath := flag.String("config", "config.yaml", "path to config.yaml")
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

	armVault(context.Background(), s, cfg, logger)

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
	aiRegistry := ai.NewRegistry(ai.StoreTools(s)...)
	server.WithAgent(&ai.Agent{Provider: &ai.SettingsProvider{Store: s}, Tools: aiRegistry, Logger: logger})

	// Plane A metrics pull-poller: periodically SSHes metrics-enabled VMs (reusing the vault) and
	// records CPU/RAM/disk/load samples; hourly downsampling (§5.2). Runs until ctx is cancelled.
	pollInterval := time.Duration(cfg.Metrics.PollIntervalSec) * time.Second
	if pollInterval <= 0 {
		pollInterval = 5 * time.Minute // default cadence (60s was too noisy for small fleets)
	}
	go metrics.New(s, ssh.New(s, logger), logger).WithInterval(pollInterval).Run(ctx)

	if err := server.Serve(ctx); err != nil {
		logging.LDD(logger, 10, "main", "SERVE_FAIL", err.Error())
		os.Exit(1)
	}

	_ = audit.Append(s.DB, logger, audit.Entry{
		Plane: audit.PlaneA, Action: "service.stop", Success: true,
	})
	logging.LDD(logger, 9, "main", "STOP", "vmpulse stopped")
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
// @purpose Create the initial owner once, when no users exist and bootstrap creds are set.
// @complexity 4
// endregion FUNC_bootstrapAdmin
func bootstrapAdmin(ctx context.Context, s *store.Store, cfg *config.Config, logger *slog.Logger) {
	user := strings.TrimSpace(cfg.Auth.BootstrapAdminUsername)
	pass := cfg.Auth.BootstrapAdminPassword
	if user == "" || pass == "" {
		return
	}
	count, err := s.CountUsers(ctx)
	if err != nil {
		logging.LDD(logger, 9, "bootstrap", "COUNT_FAIL", err.Error())
		return
	}
	if count > 0 {
		return
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
	logging.LDD(logger, 9, "bootstrap", "CREATED", "owner="+user+" (remove bootstrap creds from config now)")
}

// region FUNC_armVault [DOMAIN(9): Security; CONCEPT(7): AtRestKey; TECH(7): argon2id,config_meta]
// @purpose Derive the at-rest key from the master passphrase and a persisted salt; arm the store.
// @complexity 4
// @invariants
//   - The passphrase is NEVER persisted; only the random salt is (config_meta.vault_salt).
//   - Empty passphrase -> vault disabled (plaintext secrets).
//
// endregion FUNC_armVault
func armVault(ctx context.Context, s *store.Store, cfg *config.Config, logger *slog.Logger) {
	if !cfg.Vault.Configured() {
		logging.LDD(logger, 7, "main", "VAULT_DISABLED", "set vault.passphrase to encrypt secrets")
		return
	}
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
	s.SetVault(crypto.NewVault(cfg.Vault.Passphrase, salt))
	logging.LDD(logger, 9, "main", "VAULT_ARMED", "at-rest encryption enabled")
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
