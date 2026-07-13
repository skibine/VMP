// Package store — VM repository (CRUD + soft-delete).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): Repository; TECH(8): database/sql]
// @purpose Persist VM entities. SSH credentials are NOT stored here (Plane B vault owns them).
// @invariants
//   - Create/Update always Validate() first.
//   - List excludes archived rows unless includeArchived=true.
//   - Archive sets archived_at (soft-delete, preserves incident history); Delete is physical.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: VM, repository, CRUD, create, get, list, update, archive, soft-delete
// STRUCTURE: ▶ ┌VM┐ → ○ Validate → ⊕ INSERT/UPDATE → ⎋ id ; List → 〈archived?〉 → ∑ scan
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/skibine/vm-pulse/internal/logging"
)

// region FUNC_CreateVM [DOMAIN(8): Storage; CONCEPT(7): Create; TECH(7): database/sql]
// @purpose Insert a VM and return its new id.
// @complexity 5
// endregion FUNC_CreateVM
func (s *Store) CreateVM(ctx context.Context, v VM) (int64, error) {
	if err := v.Validate(); err != nil {
		return 0, err
	}
	// Assign the next stable ordinal (max+1). Never renumbered on delete (gaps are intentional).
	var maxNo int
	_ = s.DB.QueryRowContext(ctx, `SELECT COALESCE(MAX(display_no),0) FROM vms`).Scan(&maxNo)
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO vms
(name, display_no, hostname, ip, port_ssh, ssh_user, auth_type, provider, location_country, location_city,
 tags, group_id, notes, cost_monthly, currency, owner_user_id, agent_enabled, agent_port,
 prometheus_url, record_ssh_sessions, metrics_enabled, ai_enabled)
VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		v.Name, maxNo+1, v.Hostname, v.IP, v.PortSSH, v.SSHUser, v.AuthType, v.Provider,
		v.LocationCountry, v.LocationCity, marshalJSONcol(v.Tags), nullInt64(v.GroupID), v.Notes,
		nullFloat64(v.CostMonthly), v.Currency, nullInt64(v.OwnerUserID), toBoolInt(v.AgentEnabled),
		nullInt(v.AgentPort), v.PrometheusURL, toBoolInt(v.RecordSSHSessions), toBoolInt(v.MetricsEnabled), toBoolInt(v.AIEnabled))
	if err != nil {
		logging.LDD(s.logger, 10, "CreateVM", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateVM: %w", err)
	}
	id, _ := res.LastInsertId()
	logging.LDD(s.logger, 8, "CreateVM", "CREATED", fmt.Sprintf("id=%s no=%d name=%s", fmtID(id), maxNo+1, v.Name))
	return id, nil
}

// region FUNC_GetVM [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Fetch a single VM by id. Returns sql.ErrNoRows (wrapped) when absent.
// @complexity 4
// endregion FUNC_GetVM
func (s *Store) GetVM(ctx context.Context, id int64) (VM, error) {
	row := s.DB.QueryRowContext(ctx, vmSelectCols()+` WHERE id = ?`, id)
	v, err := scanVM(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return VM{}, ErrNotFound
		}
		return VM{}, fmt.Errorf("GetVM: %w", err)
	}
	return v, nil
}

// region FUNC_ListVMs [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose List VMs, excluding archived by default.
// @complexity 4
// endregion FUNC_ListVMs
func (s *Store) ListVMs(ctx context.Context, includeArchived bool) ([]VM, error) {
	q := vmSelectCols() + ` ORDER BY display_no ASC`
	if !includeArchived {
		q = vmSelectCols() + ` WHERE archived_at IS NULL ORDER BY display_no ASC`
	}
	rows, err := s.DB.QueryContext(ctx, q)
	if err != nil {
		return nil, fmt.Errorf("ListVMs: %w", err)
	}
	defer rows.Close()
	var out []VM
	for rows.Next() {
		v, err := scanVM(rows)
		if err != nil {
			return nil, fmt.Errorf("ListVMs scan: %w", err)
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// region FUNC_UpdateVM [DOMAIN(8): Storage; CONCEPT(7): Update; TECH(7): database/sql]
// @purpose Update all mutable VM fields by id (validates first). No-op on unknown id.
// @complexity 5
// endregion FUNC_UpdateVM
func (s *Store) UpdateVM(ctx context.Context, v VM) error {
	if err := v.Validate(); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `
UPDATE vms SET name=?, hostname=?, ip=?, port_ssh=?, ssh_user=?, auth_type=?, provider=?,
 location_country=?, location_city=?, tags=?, group_id=?, notes=?, cost_monthly=?, currency=?,
 owner_user_id=?, agent_enabled=?, agent_port=?, prometheus_url=?, record_ssh_sessions=?, metrics_enabled=?,
 ai_enabled=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now')
WHERE id=?`,
		v.Name, v.Hostname, v.IP, v.PortSSH, v.SSHUser, v.AuthType, v.Provider,
		v.LocationCountry, v.LocationCity, marshalJSONcol(v.Tags), nullInt64(v.GroupID), v.Notes,
		nullFloat64(v.CostMonthly), v.Currency, nullInt64(v.OwnerUserID), toBoolInt(v.AgentEnabled),
		nullInt(v.AgentPort), v.PrometheusURL, toBoolInt(v.RecordSSHSessions), toBoolInt(v.MetricsEnabled), toBoolInt(v.AIEnabled), v.ID)
	if err != nil {
		return fmt.Errorf("UpdateVM: %w", err)
	}
	return rowsAffected(res, "UpdateVM", v.ID)
}

// region FUNC_SetAIEnabled [DOMAIN(9): Security; CONCEPT(7): AIAccess; TECH(5): database/sql]
// @purpose Grant or revoke the AI assistant's access to a single VM (opt-in per VM).
// @complexity 2
// endregion FUNC_SetAIEnabled
func (s *Store) SetAIEnabled(ctx context.Context, id int64, enabled bool) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE vms SET ai_enabled=?, updated_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`, toBoolInt(enabled), id)
	if err != nil {
		return fmt.Errorf("SetAIEnabled: %w", err)
	}
	return rowsAffected(res, "SetAIEnabled", id)
}

// region FUNC_ArchiveVM [DOMAIN(8): Storage; CONCEPT(7): SoftDelete; TECH(5): database/sql]
// @purpose Soft-delete a VM (set archived_at), preserving its incident/check history.
// @complexity 3
// endregion FUNC_ArchiveVM
func (s *Store) ArchiveVM(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE vms SET archived_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND archived_at IS NULL`, id)
	if err != nil {
		return fmt.Errorf("ArchiveVM: %w", err)
	}
	return rowsAffected(res, "ArchiveVM", id)
}

// region FUNC_DeleteVM [DOMAIN(8): Storage; CONCEPT(7): Delete; TECH(5): database/sql]
// @purpose Physically delete a VM (owner operation; gated by auth in a later slice).
// @complexity 5
// endregion FUNC_DeleteVM
// STRUCTURE: ▶ ┌vmID┐ → ⊖ check_results(by check) → ⊖ checks → ⊖ metric_samples → ⊖ vms(cascade creds/hostkeys) → ⎷
func (s *Store) DeleteVM(ctx context.Context, id int64) error {
	tx, err := s.DB.BeginTx(ctx, nil)
	if err != nil {
		return fmt.Errorf("DeleteVM: begin: %w", err)
	}
	defer func() { _ = tx.Rollback() }()
	// check_results and metric_samples have NO foreign keys; checks FK is SET NULL. Clean them up
	// explicitly so deleting a VM removes ALL its history (checks, results, metrics) — the
	// vm_credentials/vm_hostkeys rows are removed by their ON DELETE CASCADE on the vms delete.
	stmts := []string{
		`DELETE FROM check_results WHERE check_id IN (SELECT id FROM checks WHERE vm_id = ?)`,
		`DELETE FROM checks WHERE vm_id = ?`,
		`DELETE FROM metric_samples WHERE vm_id = ?`,
	}
	for _, q := range stmts {
		if _, err := tx.ExecContext(ctx, q, id); err != nil {
			return fmt.Errorf("DeleteVM: cleanup: %w", err)
		}
	}
	res, err := tx.ExecContext(ctx, `DELETE FROM vms WHERE id = ?`, id)
	if err != nil {
		return fmt.Errorf("DeleteVM: vms: %w", err)
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("DeleteVM: commit: %w", err)
	}
	return rowsAffected(res, "DeleteVM", id)
}

// vmSelectCols returns the SELECT preamble shared by Get/List.
func vmSelectCols() string {
	return `SELECT id, name, display_no, hostname, ip, port_ssh, ssh_user, auth_type, provider,
 location_country, location_city, tags, group_id, notes, cost_monthly, currency,
 owner_user_id, agent_enabled, agent_port, prometheus_url, record_ssh_sessions, metrics_enabled,
 ai_enabled, created_at, updated_at, archived_at FROM vms`
}

// scanVM scans a VM from anything with Scan (both *sql.Row and *sql.Rows).
func scanVM(sc scanner) (VM, error) {
	var v VM
	var tags string
	var groupID, ownerID, agentPort sql.NullInt64
	var cost sql.NullFloat64
	var archived sql.NullString
	var agentEnabled, recordSSH, metricsEnabled, aiEnabled int
	err := sc.Scan(
		&v.ID, &v.Name, &v.DisplayNo, &v.Hostname, &v.IP, &v.PortSSH, &v.SSHUser, &v.AuthType, &v.Provider,
		&v.LocationCountry, &v.LocationCity, &tags, &groupID, &v.Notes, &cost, &v.Currency,
		&ownerID, &agentEnabled, &agentPort, &v.PrometheusURL, &recordSSH, &metricsEnabled,
		&aiEnabled, &v.CreatedAt, &v.UpdatedAt, &archived)
	if err != nil {
		return v, err
	}
	unmarshalJSONcol(tags, &v.Tags)
	if v.Tags == nil {
		v.Tags = []string{}
	}
	v.GroupID = toInt64Ptr(groupID)
	v.OwnerUserID = toInt64Ptr(ownerID)
	v.AgentPort = toIntPtr(agentPort)
	v.CostMonthly = toFloat64Ptr(cost)
	v.ArchivedAt = toStrPtr(archived)
	v.AgentEnabled = toBool(agentEnabled)
	v.RecordSSHSessions = toBool(recordSSH)
	v.MetricsEnabled = toBool(metricsEnabled)
	v.AIEnabled = toBool(aiEnabled)
	return v, nil
}
