// Package store — alerting models and repository.
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(8): Alerting; TECH(8): database/sql]
// @purpose Persist alert rules, delivery channels, their links, and fired alerts; plus the
//
//	global "latest result per enabled check" read-model the evaluator consumes.
//
// @invariants
//   - alert_rule_channels is the many<->many link; deleting a rule/channel cascades.
//   - channels.config is JSON; secrets are PLAINTEXT now (TODO(encrypt) in vault slice).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: alert_rules, channels, alerts, CRUD, AttachChannel, LatestCheckResults, cooldown
// STRUCTURE: ▶ models → ○ CRUD/attach → ⎋ id ; LatestCheckResults → LEFT JOIN max(id) per check
package store

import (
	"context"
	"database/sql"
	"fmt"
	"strings"

	"github.com/skibine/vm-pulse/internal/logging"
)

// region STRUCT_AlertRule [DOMAIN(8): Alerting; CONCEPT(7): Rule; TECH(6): struct]
// @purpose One alert rule. CheckType empty means "apply to all check types".
// endregion STRUCT_AlertRule
type AlertRule struct {
	ID            int64  `json:"id"`
	Name          string `json:"name"`
	CheckType     string `json:"check_type"`     // "" = all types
	TriggerStatus string `json:"trigger_status"` // warn | critical | unknown
	Severity      string `json:"severity"`       // warning | critical
	CooldownSec   int    `json:"cooldown_sec"`
	Enabled       bool   `json:"enabled"`
	CreatedAt     string `json:"created_at"`
}

func (r AlertRule) Validate() error {
	if strings.TrimSpace(r.Name) == "" {
		return ValidationError{Field: "name", Reason: "required"}
	}
	switch r.TriggerStatus {
	case "warn", "critical", "unknown":
	default:
		return ValidationError{Field: "trigger_status", Reason: "must be warn|critical|unknown"}
	}
	switch r.Severity {
	case "warning", "critical":
	default:
		return ValidationError{Field: "severity", Reason: "must be warning|critical"}
	}
	if r.CooldownSec < 0 {
		return ValidationError{Field: "cooldown_sec", Reason: "must be >= 0"}
	}
	return nil
}

// region STRUCT_Channel [DOMAIN(8): Alerting; CONCEPT(7): Delivery; TECH(6): struct]
// @purpose A delivery channel (telegram/log/...). Config holds type-specific JSON.
// endregion STRUCT_Channel
type Channel struct {
	ID        int64          `json:"id"`
	Type      string         `json:"type"`
	Name      string         `json:"name"`
	Config    map[string]any `json:"config"`
	Enabled   bool           `json:"enabled"`
	CreatedAt string         `json:"created_at"`
}

func (c Channel) Validate() error {
	if strings.TrimSpace(c.Type) == "" {
		return ValidationError{Field: "type", Reason: "required"}
	}
	if strings.TrimSpace(c.Name) == "" {
		return ValidationError{Field: "name", Reason: "required"}
	}
	return nil
}

// region STRUCT_Alert [DOMAIN(8): Alerting; CONCEPT(7): Fired; TECH(6): struct]
// @purpose A fired alert record (one per rule+check firing event).
// endregion STRUCT_Alert
type Alert struct {
	ID             int64          `json:"id"`
	RuleID         int64          `json:"rule_id"`
	CheckID        int64          `json:"check_id"`
	VMID           *int64         `json:"vm_id"`
	Severity       string         `json:"severity"`
	Message        string         `json:"message"`
	TriggeredAt    string         `json:"triggered_at"`
	AcknowledgedAt *string        `json:"acknowledged_at"`
	DeliveryLog    map[string]any `json:"delivery_log"`
}

// region STRUCT_LatestCheckResult [DOMAIN(8): Alerting; CONCEPT(6): ReadModel; TECH(6): struct]
// @purpose The newest result of an enabled check, globally (evaluator input).
// endregion STRUCT_LatestCheckResult
type LatestCheckResult struct {
	CheckID   int64   `json:"check_id"`
	CheckType string  `json:"check_type"`
	VMID      *int64  `json:"vm_id"`
	DomainID  *int64  `json:"domain_id"`
	Status    string  `json:"status"`
	LatencyMS float64 `json:"latency_ms"`
	TS        string  `json:"ts"`
}

// ── AlertRule CRUD ──────────────────────────────────────────────────────────────────

func (s *Store) CreateAlertRule(ctx context.Context, r AlertRule) (int64, error) {
	if err := r.Validate(); err != nil {
		return 0, err
	}
	ctype := r.CheckType
	if ctype != "" {
		ctype = strings.TrimSpace(ctype)
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO alert_rules (name, check_type, trigger_status, severity, cooldown_sec, enabled)
VALUES (?,?,?,?,?,?)`,
		r.Name, ctype, r.TriggerStatus, r.Severity, r.CooldownSec, toBoolInt(r.Enabled))
	if err != nil {
		logging.LDD(s.logger, 10, "CreateAlertRule", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateAlertRule: %w", err)
	}
	id, _ := res.LastInsertId()
	logging.LDD(s.logger, 8, "CreateAlertRule", "CREATED", fmt.Sprintf("id=%d name=%s", id, r.Name))
	return id, nil
}

func (s *Store) ListAlertRules(ctx context.Context) ([]AlertRule, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, COALESCE(check_type,''), trigger_status, severity, cooldown_sec, enabled, created_at
FROM alert_rules ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListAlertRules: %w", err)
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var enabled int
		if err := rows.Scan(&r.ID, &r.CheckType, &r.TriggerStatus, &r.Severity, &r.CooldownSec, &enabled, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListAlertRules scan: %w", err)
		}
		r.Enabled = enabled != 0
		out = append(out, r)
	}
	return out, rows.Err()
}

func (s *Store) DeleteAlertRule(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM alert_rules WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("DeleteAlertRule: %w", err)
	}
	return rowsAffected(res, "DeleteAlertRule", id)
}

// ── Channel CRUD ────────────────────────────────────────────────────────────────────

func (s *Store) CreateChannel(ctx context.Context, c Channel) (int64, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO channels (type, name, config, enabled) VALUES (?,?,?,?)`,
		c.Type, c.Name, s.encCol(marshalJSONcol(c.Config)), toBoolInt(c.Enabled))
	if err != nil {
		logging.LDD(s.logger, 10, "CreateChannel", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateChannel: %w", err)
	}
	id, _ := res.LastInsertId()
	logging.LDD(s.logger, 8, "CreateChannel", "CREATED", fmt.Sprintf("id=%d type=%s", id, c.Type))
	return id, nil
}

func (s *Store) ListChannels(ctx context.Context) ([]Channel, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT id, type, name, config, enabled, created_at FROM channels ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListChannels: %w", err)
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var config string
		var enabled int
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &config, &enabled, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListChannels scan: %w", err)
		}
		c.Enabled = enabled != 0
		c.Config = map[string]any{}
		unmarshalJSONcol(s.decCol(config), &c.Config)
		out = append(out, c)
	}
	return out, rows.Err()
}

func (s *Store) GetChannel(ctx context.Context, id int64) (Channel, error) {
	var c Channel
	var config string
	var enabled int
	err := s.DB.QueryRowContext(ctx, `SELECT id, type, name, config, enabled, created_at FROM channels WHERE id=?`, id).
		Scan(&c.ID, &c.Type, &c.Name, &config, &enabled, &c.CreatedAt)
	if err == sql.ErrNoRows {
		return Channel{}, ErrNotFound
	}
	if err != nil {
		return Channel{}, fmt.Errorf("GetChannel: %w", err)
	}
	c.Enabled = enabled != 0
	c.Config = map[string]any{}
	unmarshalJSONcol(s.decCol(config), &c.Config)
	return c, nil
}

func (s *Store) DeleteChannel(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM channels WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("DeleteChannel: %w", err)
	}
	return rowsAffected(res, "DeleteChannel", id)
}

// ── Rule <-> Channel link ───────────────────────────────────────────────────────────

// AttachChannel links a channel to a rule (idempotent).
func (s *Store) AttachChannel(ctx context.Context, ruleID, channelID int64) error {
	_, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO alert_rule_channels (rule_id, channel_id) VALUES (?,?)`, ruleID, channelID)
	if err != nil {
		return fmt.Errorf("AttachChannel: %w", err)
	}
	return nil
}

// ListChannelsForRule returns the channels attached to a rule.
func (s *Store) ListChannelsForRule(ctx context.Context, ruleID int64) ([]Channel, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT c.id, c.type, c.name, c.config, c.enabled, c.created_at
FROM channels c JOIN alert_rule_channels l ON l.channel_id = c.id
WHERE l.rule_id = ? ORDER BY c.id ASC`, ruleID)
	if err != nil {
		return nil, fmt.Errorf("ListChannelsForRule: %w", err)
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var config string
		var enabled int
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &config, &enabled, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListChannelsForRule scan: %w", err)
		}
		c.Enabled = enabled != 0
		c.Config = map[string]any{}
		unmarshalJSONcol(s.decCol(config), &c.Config)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ── Alerts write/read + cooldown ────────────────────────────────────────────────────

// InsertAlert records a fired alert and returns its id.
func (s *Store) InsertAlert(ctx context.Context, a Alert) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO alerts (rule_id, check_id, vm_id, severity, message, delivery_log)
VALUES (?,?,?,?,?,?)`,
		a.RuleID, a.CheckID, nullInt64(a.VMID), a.Severity, a.Message, marshalJSONcol(a.DeliveryLog))
	if err != nil {
		logging.LDD(s.logger, 10, "InsertAlert", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("InsertAlert: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// ListAlerts returns the most recent alerts (newest first), limited.
func (s *Store) ListAlerts(ctx context.Context, limit int) ([]Alert, error) {
	if limit <= 0 {
		limit = 50
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, rule_id, check_id, vm_id, severity, message, triggered_at, COALESCE(acknowledged_at,''), delivery_log
FROM alerts ORDER BY triggered_at DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("ListAlerts: %w", err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var vmID sql.NullInt64
		var ack, dlog string
		if err := rows.Scan(&a.ID, &a.RuleID, &a.CheckID, &vmID, &a.Severity, &a.Message, &a.TriggeredAt, &ack, &dlog); err != nil {
			return nil, fmt.Errorf("ListAlerts scan: %w", err)
		}
		a.VMID = toInt64Ptr(vmID)
		a.DeliveryLog = map[string]any{}
		unmarshalJSONcol(dlog, &a.DeliveryLog)
		out = append(out, a)
	}
	return out, rows.Err()
}

// LastAlertFor returns the triggered_at of the most recent alert for (ruleID, checkID),
// and false when none exists (used by the evaluator for cooldown).
func (s *Store) LastAlertFor(ctx context.Context, ruleID, checkID int64) (string, bool, error) {
	var ts string
	err := s.DB.QueryRowContext(ctx,
		`SELECT triggered_at FROM alerts WHERE rule_id=? AND check_id=? ORDER BY triggered_at DESC LIMIT 1`,
		ruleID, checkID).Scan(&ts)
	if err == sql.ErrNoRows {
		return "", false, nil
	}
	if err != nil {
		return "", false, fmt.Errorf("LastAlertFor: %w", err)
	}
	return ts, true, nil
}

// LatestCheckResults returns the newest check_result per enabled check, globally.
func (s *Store) LatestCheckResults(ctx context.Context) ([]LatestCheckResult, error) {
	const q = `
SELECT c.id, c.check_type, c.vm_id, c.domain_id,
       COALESCE(r.status,''), COALESCE(r.latency_ms,0), COALESCE(r.ts,'')
FROM checks c
LEFT JOIN check_results r
  ON r.check_id = c.id
 AND r.id = (SELECT MAX(id) FROM check_results WHERE check_id = c.id)
WHERE c.enabled = 1
ORDER BY c.id ASC`
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("LatestCheckResults: %w", err)
	}
	defer rows.Close()
	var out []LatestCheckResult
	for rows.Next() {
		var l LatestCheckResult
		var vmID, domainID sql.NullInt64
		if err := rows.Scan(&l.CheckID, &l.CheckType, &vmID, &domainID, &l.Status, &l.LatencyMS, &l.TS); err != nil {
			return nil, fmt.Errorf("LatestCheckResults scan: %w", err)
		}
		l.VMID = toInt64Ptr(vmID)
		l.DomainID = toInt64Ptr(domainID)
		out = append(out, l)
	}
	return out, rows.Err()
}
