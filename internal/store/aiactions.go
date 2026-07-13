// Package store — AI-proposed VM actions (Plane B mutating actions with approval).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): MutatingActions; TECH(7): database/sql]
// @purpose Persist AI-proposed commands so they can be approved/rejected out-of-band and audited.
//
// @invariants
//   - A pending action is never executed until status becomes approved; approval flips it for the
//     executor, which then sets done/error + output.
//   - requested_by is "ai" for model-proposed actions, or the operator username on manual runs.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ai_actions, propose command, approve, reject, mutating, audit, pending
// STRUCTURE: ▶ ┌{vm,cmd,reason}┐ → ⊕ INSERT(pending) → ◇ approve/reject → ⚡ execute → ⊕ output → ⎷
package store

import (
	"context"
	"database/sql"
	"fmt"
)

// AIAction is a proposed/executed VM command.
type AIAction struct {
	ID          int64  `json:"id"`
	VMID        int64  `json:"vm_id"`
	Command     string `json:"command"`
	Reason      string `json:"reason"`
	Status      string `json:"status"` // pending|approved|rejected|done|error
	Output      string `json:"output"`
	RequestedBy string `json:"requested_by"`
	CreatedAt   string `json:"created_at"`
	ExecutedAt  string `json:"executed_at"`
}

// SettingAIAutoApprove toggles whether AI-proposed actions execute without operator approval.
const SettingAIAutoApprove = "ai_action_auto_approve"

// CreateAIAction inserts a pending action and returns its id.
func (s *Store) CreateAIAction(ctx context.Context, a AIAction) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO ai_actions (vm_id, command, reason, status, requested_by) VALUES (?,?,?,?,?)`,
		a.VMID, a.Command, a.Reason, "pending", a.RequestedBy)
	if err != nil {
		return 0, fmt.Errorf("CreateAIAction: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// ListAIActions returns actions, optionally filtered by status (empty = all), newest first.
func (s *Store) ListAIActions(ctx context.Context, status string) ([]AIAction, error) {
	q := `SELECT id, vm_id, command, reason, status, output, requested_by, created_at, executed_at FROM ai_actions`
	var rows *sql.Rows
	var err error
	if status == "" {
		q += ` ORDER BY id DESC LIMIT 50`
		rows, err = s.DB.QueryContext(ctx, q)
	} else {
		q += ` WHERE status=? ORDER BY id DESC LIMIT 50`
		rows, err = s.DB.QueryContext(ctx, q, status)
	}
	if err != nil {
		return nil, fmt.Errorf("ListAIActions: %w", err)
	}
	defer rows.Close()
	var out []AIAction
	for rows.Next() {
		var a AIAction
		var executed sql.NullString
		if err := rows.Scan(&a.ID, &a.VMID, &a.Command, &a.Reason, &a.Status, &a.Output, &a.RequestedBy, &a.CreatedAt, &executed); err != nil {
			return nil, err
		}
		a.ExecutedAt = executed.String
		out = append(out, a)
	}
	return out, rows.Err()
}

// GetAIAction fetches a single action by id.
func (s *Store) GetAIAction(ctx context.Context, id int64) (AIAction, error) {
	var a AIAction
	var executed sql.NullString
	err := s.DB.QueryRowContext(ctx,
		`SELECT id, vm_id, command, reason, status, output, requested_by, created_at, executed_at FROM ai_actions WHERE id=?`, id).
		Scan(&a.ID, &a.VMID, &a.Command, &a.Reason, &a.Status, &a.Output, &a.RequestedBy, &a.CreatedAt, &executed)
	if err == sql.ErrNoRows {
		return AIAction{}, ErrNotFound
	}
	if err != nil {
		return AIAction{}, fmt.Errorf("GetAIAction: %w", err)
	}
	a.ExecutedAt = executed.String
	return a, nil
}

// SetAIActionStatus flips an action's status (used for approve/reject and done/error by the executor).
func (s *Store) SetAIActionStatus(ctx context.Context, id int64, status, output string) error {
	res, err := s.DB.ExecContext(ctx,
		`UPDATE ai_actions SET status=?, output=?, executed_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`,
		status, output, id)
	if err != nil {
		return fmt.Errorf("SetAIActionStatus: %w", err)
	}
	return rowsAffected(res, "SetAIActionStatus", id)
}

// IsAIAutoApprove reports whether AI actions should execute without operator approval.
func (s *Store) IsAIAutoApprove(ctx context.Context) bool {
	v, err := s.GetSetting(ctx, SettingAIAutoApprove)
	return err == nil && v == "true"
}
