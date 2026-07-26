// Package store — Check repository (CRUD).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(8): Monitoring; TECH(7): database/sql]
// @purpose Persist check definitions. Each check targets exactly one of vm_id / domain_id.
// @invariants
//   - Create/Update always Validate() first (target<->id consistency enforced).
//   - params / thresholds are JSON columns, round-tripped via map[string]any.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: Check, repository, CRUD, params, thresholds, target_type, check_type
// STRUCTURE: ▶ ┌Check┐ → ○ Validate → ⊕ INSERT/UPDATE → ⎋ id ; List → ∑ scan(unmarshal JSON)
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"

	"github.com/skibine/vm-pulse/internal/logging"
)

// region FUNC_CreateCheck [DOMAIN(8): Storage; CONCEPT(7): Create; TECH(7): database/sql]
// @purpose Insert a check and return its new id.
// @complexity 5
// endregion FUNC_CreateCheck
func (s *Store) CreateCheck(ctx context.Context, c Check) (int64, error) {
	if err := c.Validate(); err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO checks (vm_id, domain_id, target_type, check_type, params, interval_sec, enabled, thresholds, system)
VALUES (?,?,?,?,?,?,?,?,?)`,
		nullInt64(c.VMID), nullInt64(c.DomainID), c.TargetType, c.CheckType,
		marshalJSONcol(c.Params), c.IntervalSec, toBoolInt(c.Enabled), marshalJSONcol(c.Thresholds), toBoolInt(c.System))
	if err != nil {
		logging.LDD(s.logger, 10, "CreateCheck", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateCheck: %w", err)
	}
	id, _ := res.LastInsertId()
	logging.LDD(s.logger, 8, "CreateCheck", "CREATED",
		fmt.Sprintf("id=%s type=%s target=%s", fmtID(id), c.CheckType, c.TargetType))
	return id, nil
}

// region FUNC_GetCheck [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Fetch a single check by id.
// @complexity 4
// endregion FUNC_GetCheck
func (s *Store) GetCheck(ctx context.Context, id int64) (Check, error) {
	row := s.DB.QueryRowContext(ctx, checkSelectCols()+` WHERE id = ?`, id)
	c, err := scanCheck(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Check{}, ErrNotFound
		}
		return Check{}, fmt.Errorf("GetCheck: %w", err)
	}
	return c, nil
}

// region FUNC_ListChecks [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose List all checks (optionally filtered by vm_id). Monitoring engine filters enabled.
// @complexity 4
// endregion FUNC_ListChecks
func (s *Store) ListChecks(ctx context.Context, vmID *int64) ([]Check, error) {
	var rows *sql.Rows
	var err error
	if vmID != nil {
		rows, err = s.DB.QueryContext(ctx, checkSelectCols()+` WHERE vm_id = ? ORDER BY id ASC`, *vmID)
	} else {
		rows, err = s.DB.QueryContext(ctx, checkSelectCols()+` ORDER BY id ASC`)
	}
	if err != nil {
		return nil, fmt.Errorf("ListChecks: %w", err)
	}
	defer rows.Close()
	var out []Check
	for rows.Next() {
		c, err := scanCheck(rows)
		if err != nil {
			return nil, fmt.Errorf("ListChecks scan: %w", err)
		}
		out = append(out, c)
	}
	return out, rows.Err()
}

// region FUNC_UpdateCheck [DOMAIN(8): Storage; CONCEPT(7): Update; TECH(7): database/sql]
// @purpose Update all mutable check fields by id (validates first).
// @complexity 5
// endregion FUNC_UpdateCheck
func (s *Store) UpdateCheck(ctx context.Context, c Check) error {
	if err := c.Validate(); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `
UPDATE checks SET vm_id=?, domain_id=?, target_type=?, check_type=?, params=?, interval_sec=?,
 enabled=?, thresholds=? WHERE id=?`,
		nullInt64(c.VMID), nullInt64(c.DomainID), c.TargetType, c.CheckType,
		marshalJSONcol(c.Params), c.IntervalSec, toBoolInt(c.Enabled), marshalJSONcol(c.Thresholds), c.ID)
	if err != nil {
		return fmt.Errorf("UpdateCheck: %w", err)
	}
	return rowsAffected(res, "UpdateCheck", c.ID)
}

// region FUNC_DeleteCheck [DOMAIN(8): Storage; CONCEPT(7): Delete; TECH(5): database/sql]
// @purpose Physically delete a check. System checks (auto liveness) are not user-deletable.
// @complexity 3
// endregion FUNC_DeleteCheck
func (s *Store) DeleteCheck(ctx context.Context, id int64) error {
	var system int
	_ = s.DB.QueryRowContext(ctx, `SELECT system FROM checks WHERE id=?`, id).Scan(&system)
	if system != 0 {
		return ErrSystemCheck
	}
	res, err := s.DB.ExecContext(ctx, `DELETE FROM checks WHERE id=? AND system=0`, id)
	if err != nil {
		return fmt.Errorf("DeleteCheck: %w", err)
	}
	return rowsAffected(res, "DeleteCheck", id)
}

// ErrSystemCheck signals an attempt to mutate a system-managed check (e.g. the auto liveness probe).
var ErrSystemCheck = errors.New("system check cannot be modified")

// EnsureSystemLiveness makes sure a VM has exactly one system liveness check (the composite
// ping/ssh/web/tls probe that drives the fleet dot). Idempotent; re-creates if missing.
func (s *Store) EnsureSystemLiveness(ctx context.Context, vmID int64, portSSH int) error {
	var n int
	_ = s.DB.QueryRowContext(ctx, `SELECT COUNT(*) FROM checks WHERE vm_id=? AND system=1`, vmID).Scan(&n)
	if n > 0 {
		return nil
	}
	port := portSSH
	if port == 0 {
		port = 22
	}
	_, err := s.CreateCheck(ctx, Check{
		VMID: &vmID, TargetType: "vm", CheckType: "liveness", Enabled: true, IntervalSec: 60,
		System: true, Params: map[string]any{"port": port},
	})
	return err
}

// EnsureSystemExposures makes sure a VM has exactly one system exposures check (the periodic
// curated security scan) at a 1h cadence (10-probe network scan — frequent enough that a fixed
// exposure clears within the hour, light enough for a small fleet). Idempotent; also bumps any
// legacy 6h interval to 1h. Filtered by check_type because liveness is also a system check.
func (s *Store) EnsureSystemExposures(ctx context.Context, vmID int64) error {
	var id int64
	var interval int
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, interval_sec FROM checks WHERE vm_id=? AND system=1 AND check_type='exposures' LIMIT 1`, vmID).Scan(&id, &interval)
	if err == nil {
		if interval != 3600 {
			_, _ = s.DB.ExecContext(ctx, `UPDATE checks SET interval_sec=3600 WHERE id=?`, id)
		}
		return nil
	}
	_, err = s.CreateCheck(ctx, Check{
		VMID: &vmID, TargetType: "vm", CheckType: "exposures", Enabled: true, IntervalSec: 60 * 60,
		System: true, Params: map[string]any{},
	})
	return err
}

// SystemCheckID returns the id of a VM's system check of the given type (e.g. "exposures"),
// or 0 if none exists. Used so an on-demand scan can persist its result into the right check.
func (s *Store) SystemCheckID(ctx context.Context, vmID int64, checkType string) (int64, error) {
	var id int64
	err := s.DB.QueryRowContext(ctx,
		`SELECT id FROM checks WHERE vm_id=? AND system=1 AND check_type=? LIMIT 1`, vmID, checkType).Scan(&id)
	if err != nil {
		return 0, err
	}
	return id, nil
}

// PropagateExposuresResult applies an exposures scan result to every non-archived VM whose scan
// target (ip OR hostname) matches — because probing the same host yields the same result. exceptVMID
// is the already-persisted source and is skipped to avoid a duplicate row. This is what makes a fix
// on a shared host clear the alert fleet-wide: scan ONE VM on the host, all the rest update too.
// Returns the number of additional VMs updated.
//
// BUG_FIX_CONTEXT: the pool is SetMaxOpenConns(1) (SQLite serialization). We MUST collect the VM ids
// and close the rows iterator BEFORE issuing per-VM queries — nesting a query inside rows.Next()
// self-deadlocks on the single connection and hangs every DB access (incl. /healthz).
func (s *Store) PropagateExposuresResult(ctx context.Context, exceptVMID int64, target, status, message string, detail map[string]any) (int, error) {
	if target == "" {
		return 0, nil
	}
	rows, err := s.DB.QueryContext(ctx,
		`SELECT id FROM vms WHERE (ip=? OR hostname=?) AND archived_at IS NULL`, target, target)
	if err != nil {
		return 0, err
	}
	var vmIDs []int64
	for rows.Next() {
		var vmID int64
		if err := rows.Scan(&vmID); err == nil && vmID != exceptVMID {
			vmIDs = append(vmIDs, vmID)
		}
	}
	qErr := rows.Err()
	rows.Close() // release the single connection before per-VM queries

	updated := 0
	for _, vmID := range vmIDs {
		checkID, err := s.SystemCheckID(ctx, vmID, "exposures")
		if err != nil || checkID == 0 {
			continue
		}
		if _, err := s.InsertCheckResult(ctx, checkID, status, 0, message, detail); err == nil {
			updated++
		}
	}
	return updated, qErr
}

func checkSelectCols() string {
	return `SELECT id, vm_id, domain_id, target_type, check_type, params, interval_sec, enabled, thresholds, system, created_at FROM checks`
}

func scanCheck(sc scanner) (Check, error) {
	var c Check
	var params, thresholds string
	var vmID, domainID sql.NullInt64
	var enabled, system int
	err := sc.Scan(&c.ID, &vmID, &domainID, &c.TargetType, &c.CheckType, &params,
		&c.IntervalSec, &enabled, &thresholds, &system, &c.CreatedAt)
	if err != nil {
		return c, err
	}
	c.VMID = toInt64Ptr(vmID)
	c.DomainID = toInt64Ptr(domainID)
	c.Enabled = toBool(enabled)
	c.System = toBool(system)
	c.Params = map[string]any{}
	c.Thresholds = map[string]any{}
	unmarshalJSONcol(params, &c.Params)
	unmarshalJSONcol(thresholds, &c.Thresholds)
	return c, nil
}
