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
	VMID          *int64 `json:"vm_id,omitempty"` // scope: nil = all VMs, set = only that VM
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
INSERT INTO alert_rules (name, check_type, trigger_status, severity, cooldown_sec, enabled, vm_id)
VALUES (?,?,?,?,?,?,?)`,
		r.Name, ctype, r.TriggerStatus, r.Severity, r.CooldownSec, toBoolInt(r.Enabled), nullInt64(r.VMID))
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
SELECT id, COALESCE(check_type,''), trigger_status, severity, cooldown_sec, enabled, created_at, vm_id
FROM alert_rules ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListAlertRules: %w", err)
	}
	defer rows.Close()
	var out []AlertRule
	for rows.Next() {
		var r AlertRule
		var enabled int
		var vmID sql.NullInt64
		if err := rows.Scan(&r.ID, &r.CheckType, &r.TriggerStatus, &r.Severity, &r.CooldownSec, &enabled, &r.CreatedAt, &vmID); err != nil {
			return nil, fmt.Errorf("ListAlertRules scan: %w", err)
		}
		r.Enabled = enabled != 0
		r.VMID = toInt64Ptr(vmID)
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

// UpdateChannel updates a channel's mutable fields (type/name/config/enabled) by id.
func (s *Store) UpdateChannel(ctx context.Context, c Channel) error {
	if _, err := s.DB.ExecContext(ctx,
		`UPDATE channels SET type=?, name=?, config=?, enabled=? WHERE id=?`,
		c.Type, c.Name, s.encCol(marshalJSONcol(c.Config)), toBoolInt(c.Enabled), c.ID); err != nil {
		return fmt.Errorf("UpdateChannel: %w", err)
	}
	return nil
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

// AlertFilter drives ListAlertsFiltered (the bell modal's "alerts" tab).
type AlertFilter struct {
	Severity   string // warning | critical | "" = all
	VMID       *int64 // nil = all servers
	From       string // YYYY-MM-DD inclusive
	To         string // YYYY-MM-DD inclusive
	UnackOnly  bool   // only rows not yet acknowledged (tab unread counter)
	Limit      int
	Offset     int
}

// region FUNC_ListAlertsFiltered [DOMAIN(8): Alerting; CONCEPT(7): ReadHistory; TECH(6): database/sql]
// @purpose Paged fired-alert history for the modal: severity/vm/date filters, triggered_at DESC,
//
//	with a total count for pagination.
//
// @complexity 5
// endregion FUNC_ListAlertsFiltered
func (s *Store) ListAlertsFiltered(ctx context.Context, f AlertFilter) ([]Alert, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	where := " WHERE 1=1"
	var args []any
	if f.Severity != "" {
		where += " AND severity = ?"
		args = append(args, f.Severity)
	}
	if f.VMID != nil {
		where += " AND vm_id = ?"
		args = append(args, *f.VMID)
	}
	if f.UnackOnly {
		where += " AND COALESCE(acknowledged_at,'') = ''"
	}
	if f.From != "" {
		where += " AND triggered_at >= ?"
		args = append(args, f.From)
	}
	if f.To != "" {
		where += " AND triggered_at < date(?, '+1 day')"
		args = append(args, f.To)
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM alerts"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListAlertsFiltered count: %w", err)
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, rule_id, check_id, vm_id, severity, message, triggered_at, COALESCE(acknowledged_at,''), COALESCE(delivery_log,'')
FROM alerts`+where+` ORDER BY triggered_at DESC, id DESC LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListAlertsFiltered: %w", err)
	}
	defer rows.Close()
	var out []Alert
	for rows.Next() {
		var a Alert
		var vmID sql.NullInt64
		var ack, dlog string
		if err := rows.Scan(&a.ID, &a.RuleID, &a.CheckID, &vmID, &a.Severity, &a.Message, &a.TriggeredAt, &ack, &dlog); err != nil {
			return nil, 0, fmt.Errorf("ListAlertsFiltered scan: %w", err)
		}
		a.VMID = toInt64Ptr(vmID)
		a.DeliveryLog = map[string]any{}
		unmarshalJSONcol(dlog, &a.DeliveryLog)
		out = append(out, a)
	}
	return out, total, rows.Err()
}

// region FUNC_AcknowledgeAlert [DOMAIN(8): Alerting; CONCEPT(6): Acknowledge; TECH(5): database/sql]
// @purpose Mark one fired alert acknowledged (the "read" of the alerts tab): it leaves the
//
//	unack counter and dims in the list. Idempotent.
//
// @complexity 2
// endregion FUNC_AcknowledgeAlert
func (s *Store) AcknowledgeAlert(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE alerts SET acknowledged_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND COALESCE(acknowledged_at,'')=''`, id)
	if err != nil {
		return fmt.Errorf("AcknowledgeAlert: %w", err)
	}
	return nil
}

// region FUNC_AcknowledgeAllAlerts [DOMAIN(8): Alerting; CONCEPT(6): Acknowledge; TECH(5): database/sql]
// @purpose Acknowledge every unacknowledged alert ("mark all read" of the alerts tab).
// @complexity 2
// endregion FUNC_AcknowledgeAllAlerts
func (s *Store) AcknowledgeAllAlerts(ctx context.Context) error {
	_, err := s.DB.ExecContext(ctx,
		`UPDATE alerts SET acknowledged_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE COALESCE(acknowledged_at,'')=''`)
	if err != nil {
		return fmt.Errorf("AcknowledgeAllAlerts: %w", err)
	}
	return nil
}

// region FUNC_DeleteAlerts [DOMAIN(8): Alerting; CONCEPT(7): Purge; TECH(5): database/sql]
// @purpose Delete fired-alert history: everything, or only rows triggered before a date.
//
//	Alerts are delivery records (the rules/config live elsewhere) — history purge is safe.
//
// @complexity 3
// endregion FUNC_DeleteAlerts
func (s *Store) DeleteAlerts(ctx context.Context, before string) (int64, error) {
	var res sql.Result
	var err error
	if before != "" {
		res, err = s.DB.ExecContext(ctx, `DELETE FROM alerts WHERE triggered_at < date(?, '+1 day')`, before)
	} else {
		res, err = s.DB.ExecContext(ctx, `DELETE FROM alerts`)
	}
	if err != nil {
		return 0, fmt.Errorf("DeleteAlerts: %w", err)
	}
	n, _ := res.RowsAffected()
	logging.LDD(s.logger, 8, "DeleteAlerts", "DELETED", fmt.Sprintf("rows=%d before=%s", n, before))
	return n, nil
}

// LastAlertFor returns the triggered_at of the most recent alert for (ruleID, checkID),
// and false when none exists (used by the evaluator for cooldown).
func (s *Store) LastAlertFor(ctx context.Context, ruleID, checkID int64) (string, bool, error) {	var ts string
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

// SetAlertRuleEnabled toggles a rule on/off without losing its config (used by the VM "alert on/off").
func (s *Store) SetAlertRuleEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := s.DB.ExecContext(ctx, `UPDATE alert_rules SET enabled=? WHERE id=?`, toBoolInt(enabled), id)
	if err != nil {
		return fmt.Errorf("SetAlertRuleEnabled: %w", err)
	}
	return rowsAffected(res, "SetAlertRuleEnabled", id)
}

// ── alert_state (edge-triggered transitions) ────────────────────────────────────────

// MutedVMIDs returns the set of VM ids excluded from fleet-wide (vm_id=NULL) rules.
func (s *Store) MutedVMIDs(ctx context.Context) (map[int64]bool, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT vm_id FROM alert_mutes`)
	if err != nil {
		return nil, fmt.Errorf("MutedVMIDs: %w", err)
	}
	defer rows.Close()
	out := map[int64]bool{}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			return nil, fmt.Errorf("MutedVMIDs scan: %w", err)
		}
		out[id] = true
	}
	return out, rows.Err()
}

// SetAlertMute mutes (on=true) or unmutes a VM for fleet-wide rules.
func (s *Store) SetAlertMute(ctx context.Context, vmID int64, on bool) error {
	if on {
		_, err := s.DB.ExecContext(ctx, `INSERT OR IGNORE INTO alert_mutes (vm_id) VALUES (?)`, vmID)
		if err != nil {
			return fmt.Errorf("SetAlertMute(on): %w", err)
		}
		return nil
	}
	_, err := s.DB.ExecContext(ctx, `DELETE FROM alert_mutes WHERE vm_id=?`, vmID)
	if err != nil {
		return fmt.Errorf("SetAlertMute(off): %w", err)
	}
	return nil
}

// ── per-server alert channels (where a server's alerts are delivered) ────────────────

// ListVMChannels returns the delivery channels attached to a server's liveness alert.
func (s *Store) ListVMChannels(ctx context.Context, vmID int64) ([]Channel, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT c.id, c.type, c.name, c.config, c.enabled, c.created_at
FROM channels c JOIN vm_alert_channels v ON v.channel_id = c.id
WHERE v.vm_id = ? ORDER BY c.id ASC`, vmID)
	if err != nil {
		return nil, fmt.Errorf("ListVMChannels: %w", err)
	}
	defer rows.Close()
	var out []Channel
	for rows.Next() {
		var c Channel
		var config string
		var enabled int
		if err := rows.Scan(&c.ID, &c.Type, &c.Name, &config, &enabled, &c.CreatedAt); err != nil {
			return nil, fmt.Errorf("ListVMChannels scan: %w", err)
		}
		c.Enabled = enabled != 0
		c.Config = map[string]any{}
		unmarshalJSONcol(s.decCol(config), &c.Config)
		out = append(out, c)
	}
	return out, rows.Err()
}

// ListAllVMChannelIDs returns every (vm_id -> []channel_id) mapping in one query. Used by the
// fleet/sidebar batch endpoint so the UI does not fan out one request per VM (N+1) just to render
// the bells — only the id sets are needed for coverage + the fleet picker intersection.
func (s *Store) ListAllVMChannelIDs(ctx context.Context) (map[int64][]int64, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT vm_id, channel_id FROM vm_alert_channels ORDER BY vm_id, channel_id`)
	if err != nil {
		return nil, fmt.Errorf("ListAllVMChannelIDs: %w", err)
	}
	defer rows.Close()
	out := map[int64][]int64{}
	for rows.Next() {
		var vmID, chID int64
		if err := rows.Scan(&vmID, &chID); err != nil {
			return nil, fmt.Errorf("ListAllVMChannelIDs scan: %w", err)
		}
		out[vmID] = append(out[vmID], chID)
	}
	return out, rows.Err()
}

// SetVMChannels replaces a server's alert channels with the given set (the picker sends the full set).
func (s *Store) SetVMChannels(ctx context.Context, vmID int64, channelIDs []int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("SetVMChannels begin: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM vm_alert_channels WHERE vm_id=?`, vmID); err != nil {
		_ = tx.Rollback()
		return fmt.Errorf("SetVMChannels clear: %w", err)
	}
	for _, id := range channelIDs {
		if _, err := tx.ExecContext(ctx, `INSERT OR IGNORE INTO vm_alert_channels (vm_id, channel_id) VALUES (?,?)`, vmID, id); err != nil {
			_ = tx.Rollback()
			return fmt.Errorf("SetVMChannels insert: %w", err)
		}
	}
	return tx.Commit()
}

// GetAlertState returns the last seen status for (ruleID, checkID); "" when none recorded.
func (s *Store) GetAlertState(ctx context.Context, ruleID, checkID int64) (string, error) {
	var st string
	err := s.DB.QueryRowContext(ctx,
		`SELECT last_status FROM alert_state WHERE rule_id=? AND check_id=?`, ruleID, checkID).Scan(&st)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", fmt.Errorf("GetAlertState: %w", err)
	}
	return st, nil
}

// ListAlertState loads every (rule_id,check_id)->last_status row in one query, keyed by
// AlertStateKey(ruleID,checkID). Used by the evaluator's hot loop so it does one round-trip per
// cycle instead of one per (rule,check) pair.
func (s *Store) ListAlertState(ctx context.Context) (map[int64]string, error) {
	rows, err := s.DB.QueryContext(ctx, `SELECT rule_id, check_id, last_status FROM alert_state`)
	if err != nil {
		return nil, fmt.Errorf("ListAlertState: %w", err)
	}
	defer rows.Close()
	out := map[int64]string{}
	for rows.Next() {
		var rid, cid int64
		var st string
		if err := rows.Scan(&rid, &cid, &st); err != nil {
			return nil, fmt.Errorf("ListAlertState scan: %w", err)
		}
		out[AlertStateKey(rid, cid)] = st
	}
	return out, rows.Err()
}

// AlertStateKey packs (ruleID, checkID) into a single int64 map key shared by ListAlertState and its
// consumers. checkID is assumed < 1e12.
func AlertStateKey(ruleID, checkID int64) int64 { return ruleID*1_000_000_000_000 + checkID }

// SetAlertState records the last seen status for (ruleID, checkID) (upsert).
func (s *Store) SetAlertState(ctx context.Context, ruleID, checkID int64, status string) error {
	_, err := s.DB.ExecContext(ctx,
		`INSERT INTO alert_state (rule_id, check_id, last_status) VALUES (?,?,?)
		 ON CONFLICT(rule_id, check_id) DO UPDATE SET last_status=excluded.last_status`,
		ruleID, checkID, status)
	if err != nil {
		return fmt.Errorf("SetAlertState: %w", err)
	}
	return nil
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
