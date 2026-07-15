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
