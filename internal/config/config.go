// Package config loads VM Pulse configuration and resolves the deployment mode.
//
// region MODULE_CONTRACT [DOMAIN(7): Configuration; CONCEPT(8): DeploymentMode; TECH(8): yaml]
// @purpose Provide a single typed Config object describing how the instance runs
//
//	(local vs server mode, listen address, DB path, log level). The mode drives
//	the security posture (see foundation-v2 §2, §9).
//
// @io (path string, logger *slog.Logger) -> (*Config, error)
// @uses gopkg.in/yaml.v3, os, github.com/skibine/vm-pulse/internal/logging
// @invariants
//   - Load NEVER returns a Config with an empty Mode; missing mode defaults to "local".
//   - Local mode is the fail-secure default (less attack surface).
//   - A missing config file does NOT error; it yields Default() + a [IMP:7] warning.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: config, yaml, mode, local, server, listen, db_path, log_level, bootstrap
// STRUCTURE: ▶ ┌path┐ → ○ read → ⚡ yaml.Unmarshal → 〈missing? Default〉 → ⊕ validate → ⎷ *Config
package config

import (
	"fmt"
	"log/slog"
	"os"
	"strings"

	"github.com/skibine/vm-pulse/internal/logging"
	"gopkg.in/yaml.v3"
)

// Mode constants. ModeLocal binds localhost (soft security); ModeServer binds 0.0.0.0
// (strict security: TLS, 2FA, rate-limit per foundation-v2 §9).
const (
	ModeLocal  = "local"
	ModeServer = "server"
)

// region STRUCT_Config [DOMAIN(7): Configuration; CONCEPT(7): Settings; TECH(8): struct]
// @purpose Hold all runtime settings for a VM Pulse instance.
// endregion STRUCT_Config
type Config struct {
	Mode     string  `yaml:"mode"`      // "local" | "server"
	Listen   string  `yaml:"listen"`    // address:port, e.g. "127.0.0.1:8443"
	DBPath   string  `yaml:"db_path"`   // SQLite file path
	LogLevel string  `yaml:"log_level"` // debug | info | warn
	AI       AI      `yaml:"ai"`
	Auth     Auth    `yaml:"auth"`
	Vault    Vault   `yaml:"vault"`
	Metrics  Metrics `yaml:"metrics"`
}

// Metrics configures the credential-free pull metrics poller (Plane A, SSH pull-over-SSH).
type Metrics struct {
	PollIntervalSec int `yaml:"poll_interval_sec"` // poll cadence; default 300 (5 min)
}

// region STRUCT_Auth [DOMAIN(9): Configuration; CONCEPT(8): Bootstrap; TECH(6): struct]
// @purpose First-run bootstrap admin credentials. Set both once to create the initial owner,
//
//	then remove them from config.yaml. Empty password = no bootstrap attempt.
//
// endregion STRUCT_Auth
type Auth struct {
	BootstrapAdminUsername string `yaml:"bootstrap_admin_username"`
	BootstrapAdminPassword string `yaml:"bootstrap_admin_password"`
}

// region STRUCT_Vault [DOMAIN(9): Security; CONCEPT(8): AtRestKey; TECH(6): struct]
// @purpose Master passphrase for at-rest secret encryption (AES-256-GCM, argon2id key). The
//
//	passphrase is NEVER stored in the DB; only a derived salt is (config_meta). Empty
//	passphrase disables the vault (secrets stored plaintext). Local-mode compromise:
//	keep config.yaml at 0600; interactive unlock / OS keyring are future options.
//
// endregion STRUCT_Vault
type Vault struct {
	Passphrase string `yaml:"passphrase"`
}

// Configured reports whether the vault will arm.
func (v Vault) Configured() bool { return strings.TrimSpace(v.Passphrase) != "" }

// region STRUCT_AI [DOMAIN(7): Configuration; CONCEPT(8): AIProvider; TECH(7): struct]
// @purpose LLM provider settings. Empty APIKey means AI is disabled (chat endpoint -> 503).
//
//	APIURL targets any OpenAI-compatible /v1 endpoint (OpenAI, OpenRouter, local, ...).
//
// endregion STRUCT_AI
type AI struct {
	APIURL string `yaml:"api_url"` // e.g. "https://api.openai.com/v1"
	APIKey string `yaml:"api_key"` // empty = disabled
	Model  string `yaml:"model"`   // e.g. "gpt-4o-mini"
}

// Configured reports whether AI is usable (api_url + api_key + model all set).
func (a AI) Configured() bool {
	return strings.TrimSpace(a.APIURL) != "" && strings.TrimSpace(a.APIKey) != "" && strings.TrimSpace(a.Model) != ""
}

// region FUNC_Default [DOMAIN(7): Configuration; CONCEPT(6): Defaults; TECH(6): pure]
// @purpose Provide safe fail-secure defaults (local mode, localhost bind) so an instance
//
//	never accidentally exposes itself publicly without an explicit choice.
//
// @io () -> *Config
// @complexity 2
// endregion FUNC_Default
func Default() *Config {
	return &Config{
		Mode:     ModeLocal,
		Listen:   "127.0.0.1:8443",
		DBPath:   "data/vmpulse.sqlite",
		LogLevel: "info",
	}
}

// region FUNC_Load [DOMAIN(7): Configuration; CONCEPT(8): FileLoad; TECH(8): yaml]
// @purpose Read and parse config.yaml into a validated Config, falling back to safe
//
//	defaults when the file is absent (first-run / fresh checkout scenario).
//
// @io (path string, logger *slog.Logger) -> (*Config, error)
// @complexity 5
// @invariants
//   - A non-existent path yields Default() and a nil error (idempotent first-run).
//   - An invalid mode value is normalized to ModeLocal with a [IMP:7] warning.
//
// endregion FUNC_Load
func Load(path string, logger *slog.Logger) (*Config, error) {
	cfg := Default()
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			logging.LDD(logger, 7, "Load", "NO_CONFIG",
				fmt.Sprintf("config file not found at %s; using safe defaults", path))
			return cfg, nil
		}
		logging.LDD(logger, 10, "Load", "READ_FAIL", err.Error())
		return nil, fmt.Errorf("read config: %w", err)
	}
	if err := yaml.Unmarshal(data, cfg); err != nil {
		logging.LDD(logger, 10, "Load", "PARSE_FAIL", err.Error())
		return nil, fmt.Errorf("parse config: %w", err)
	}
	cfg.normalize(logger)
	logging.LDD(logger, 8, "Load", "MODE", fmt.Sprintf("resolved mode=%s listen=%s", cfg.Mode, cfg.Listen))
	return cfg, nil
}

// region FUNC_normalize [DOMAIN(7): Configuration; CONCEPT(6): Validation; TECH(6): pure]
// @purpose Enforce invariants on loaded values: lowercase mode, valid mode set, non-empty
//
//	listen/db_path. Invalid mode collapses to the safe local default.
//
// @complexity 3
// endregion FUNC_normalize
func (c *Config) normalize(logger *slog.Logger) {
	c.Mode = strings.ToLower(strings.TrimSpace(c.Mode))
	if c.Mode != ModeLocal && c.Mode != ModeServer {
		logging.LDD(logger, 7, "normalize", "BAD_MODE",
			fmt.Sprintf("unknown mode %q -> defaulting to %s", c.Mode, ModeLocal))
		c.Mode = ModeLocal
	}
	if strings.TrimSpace(c.Listen) == "" {
		if c.Mode == ModeServer {
			c.Listen = "0.0.0.0:8443"
		} else {
			c.Listen = "127.0.0.1:8443"
		}
	}
	if strings.TrimSpace(c.DBPath) == "" {
		c.DBPath = "data/vmpulse.sqlite"
	}
	if strings.TrimSpace(c.LogLevel) == "" {
		c.LogLevel = "info"
	}
	if strings.TrimSpace(c.AI.APIURL) == "" {
		c.AI.APIURL = "https://api.openai.com/v1"
	}
}

// IsServer reports whether strict (public) security posture applies.
func (c *Config) IsServer() bool { return c.Mode == ModeServer }
