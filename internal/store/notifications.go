// Package store — in-app notification center (reminder delivery channel "in-app").
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(7]: InApp; TECH(7]: database/sql]
// @purpose Persist reminder/system notifications so they surface inside VMPulse (bell badge +
//
//	toast) even if the browser was closed when the reminder fired; dismissed via read_at.
//
// @io CreateNotification / ListNotifications / MarkNotificationRead / CountUnreadNotifications
// @invariants
//   - read_at NULL = unread (drives the bell badge count).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: notifications, in-app, bell, toast, unread, reminder, center
// STRUCTURE: ▶ ┌Notification┐ → ○ INSERT → ⊕ ListNotifications(unread) → 〈read?〉 → ⎷ mark
package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/skibine/vm-pulse/internal/logging"
)

// region FUNC_CreateNotification [DOMAIN(7): Alerting; CONCEPT(6): Create; TECH(6): database/sql]
// @purpose Insert an in-app notification; returns its id.
// @complexity 3
// endregion FUNC_CreateNotification
func (s *Store) CreateNotification(ctx context.Context, n Notification) (int64, error) {
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO notifications (title, body, kind, ref_id) VALUES (?,?,?,?)`,
		n.Title, n.Body, n.Kind, nullInt64(n.RefID))
	if err != nil {
		logging.LDD(s.logger, 10, "CreateNotification", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateNotification: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// region FUNC_ListNotifications [DOMAIN(7): Alerting; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Return the most recent notifications (unread first, then read), capped at limit.
// @complexity 4
// endregion FUNC_ListNotifications
func (s *Store) ListNotifications(ctx context.Context, limit int) ([]Notification, error) {
	if limit <= 0 {
		limit = 30
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, title, body, kind, ref_id, created_at, COALESCE(read_at,'')
FROM notifications ORDER BY (read_at IS NULL) DESC, created_at DESC, id DESC LIMIT ?`, limit)
	if err != nil {
		return nil, fmt.Errorf("ListNotifications: %w", err)
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var refID sql.NullInt64
		var read string
		if err := rows.Scan(&n.ID, &n.Title, &n.Body, &n.Kind, &refID, &n.CreatedAt, &read); err != nil {
			return nil, fmt.Errorf("ListNotifications scan: %w", err)
		}
		n.RefID = toInt64Ptr(refID)
		n.ReadAt = read
		out = append(out, n)
	}
	return out, rows.Err()
}

// region FUNC_CountUnreadNotifications [DOMAIN(7): Alerting; CONCEPT(6): Read; TECH(5): database/sql]
// @purpose Count unread notifications (drives the bell badge).
// @complexity 2
// endregion FUNC_CountUnreadNotifications
func (s *Store) CountUnreadNotifications(ctx context.Context) (int, error) {
	var n int
	if err := s.DB.QueryRowContext(ctx, `SELECT count(*) FROM notifications WHERE read_at IS NULL`).Scan(&n); err != nil {
		return 0, fmt.Errorf("CountUnreadNotifications: %w", err)
	}
	return n, nil
}

// region FUNC_MarkNotificationRead [DOMAIN(7): Alerting; CONCEPT(6): Update; TECH(5): database/sql]
// @purpose Mark a single notification read; if it came from a one-shot reminder (no repeat), drop
// @purpose the reminder too — the alert is "executed" once the user reads it.
// @complexity 3
// endregion FUNC_MarkNotificationRead
func (s *Store) MarkNotificationRead(ctx context.Context, id int64) error {
	if _, err := s.DB.ExecContext(ctx, `UPDATE notifications SET read_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=? AND read_at IS NULL`, id); err != nil {
		return fmt.Errorf("MarkNotificationRead: %w", err)
	}
	// A reminder alert is "executed" once read: drop the producing one-shot reminder (no repeat).
	_, _ = s.DeleteOneShotReminderForNotification(ctx, id)
	return nil
}

// region FUNC_MarkAllNotificationsRead [DOMAIN(7): Alerting; CONCEPT(6): Update; TECH(5): database/sql]
// @purpose Mark every unread notification read and delete the one-shot reminders behind them.
// @complexity 3
// endregion FUNC_MarkAllNotificationsRead
func (s *Store) MarkAllNotificationsRead(ctx context.Context) error {
	// Snapshot unread reminder notifications first so their one-shot reminders can be dropped once
	// everything is marked read.
	var ids []int64
	rows, err := s.DB.QueryContext(ctx, `SELECT id FROM notifications WHERE kind='reminder' AND read_at IS NULL AND ref_id IS NOT NULL`)
	if err != nil {
		return fmt.Errorf("MarkAllNotificationsRead collect: %w", err)
	}
	for rows.Next() {
		var id int64
		if err := rows.Scan(&id); err != nil {
			rows.Close()
			return fmt.Errorf("MarkAllNotificationsRead scan: %w", err)
		}
		ids = append(ids, id)
	}
	rows.Close()
	if _, err := s.DB.ExecContext(ctx, `UPDATE notifications SET read_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE read_at IS NULL`); err != nil {
		return fmt.Errorf("MarkAllNotificationsRead: %w", err)
	}
	for _, id := range ids {
		_, _ = s.DeleteOneShotReminderForNotification(ctx, id)
	}
	return nil
}

// region FUNC_DeleteOneShotReminderForNotification [DOMAIN(8): Alerting; CONCEPT(7): Execute; TECH(5): database/sql]
// @purpose Treat a reminder alert as "executed" and remove its one-shot (repeat_days<=0) reminder.
// @purpose Idempotent: a missing notification or an already-deleted reminder is a no-op (the
// @purpose reminder may already have been dropped earlier on a successful external-channel send).
// @complexity 4
// endregion FUNC_DeleteOneShotReminderForNotification
func (s *Store) DeleteOneShotReminderForNotification(ctx context.Context, notifID int64) (bool, error) {
	var kind string
	var refID sql.NullInt64
	if err := s.DB.QueryRowContext(ctx, `SELECT kind, ref_id FROM notifications WHERE id=?`, notifID).Scan(&kind, &refID); err != nil {
		return false, nil // not found — no-op
	}
	if kind != "reminder" || !refID.Valid {
		return false, nil
	}
	var repeatDays int
	if err := s.DB.QueryRowContext(ctx, `SELECT repeat_days FROM domain_reminders WHERE id=?`, refID.Int64).Scan(&repeatDays); err != nil {
		return false, nil // reminder already gone — no-op
	}
	if repeatDays > 0 {
		return false, nil // repeating — keep it
	}
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM domain_reminders WHERE id=?`, refID.Int64); err != nil {
		return false, fmt.Errorf("DeleteOneShotReminderForNotification: %w", err)
	}
	return true, nil
}

// NotificationFilter drives ListNotificationsFiltered (the "show all notifications" modal).
type NotificationFilter struct {
	UnreadOnly bool
	Kind       string // alert | reminder | test | "" = all
	Limit      int
	Offset     int
}

// region FUNC_ListNotificationsFiltered [DOMAIN(7): Alerting; CONCEPT(6): ReadHistory; TECH(6): database/sql]
// @purpose Paged notification HISTORY for the bell modal: created_at DESC (no "unread first" —
//
//	this is a browsable log, not an inbox), with unread/kind filters and a total count.
//
// @complexity 4
// endregion FUNC_ListNotificationsFiltered
func (s *Store) ListNotificationsFiltered(ctx context.Context, f NotificationFilter) ([]Notification, int, error) {
	if f.Limit <= 0 {
		f.Limit = 50
	}
	where := " WHERE 1=1"
	var args []any
	if f.UnreadOnly {
		where += " AND read_at IS NULL"
	}
	if f.Kind != "" {
		where += " AND kind = ?"
		args = append(args, f.Kind)
	}
	var total int
	if err := s.DB.QueryRowContext(ctx, "SELECT COUNT(*) FROM notifications"+where, args...).Scan(&total); err != nil {
		return nil, 0, fmt.Errorf("ListNotificationsFiltered count: %w", err)
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, title, body, kind, ref_id, created_at, COALESCE(read_at,'')
FROM notifications`+where+` ORDER BY created_at DESC, id DESC LIMIT ? OFFSET ?`,
		append(args, f.Limit, f.Offset)...)
	if err != nil {
		return nil, 0, fmt.Errorf("ListNotificationsFiltered: %w", err)
	}
	defer rows.Close()
	var out []Notification
	for rows.Next() {
		var n Notification
		var refID sql.NullInt64
		var read string
		if err := rows.Scan(&n.ID, &n.Title, &n.Body, &n.Kind, &refID, &n.CreatedAt, &read); err != nil {
			return nil, 0, fmt.Errorf("ListNotificationsFiltered scan: %w", err)
		}
		n.RefID = toInt64Ptr(refID)
		n.ReadAt = read
		out = append(out, n)
	}
	return out, total, rows.Err()
}

// region FUNC_DeleteNotifications [DOMAIN(7): Alerting; CONCEPT(6): Purge; TECH(5): database/sql]
// @purpose Bulk-delete notifications: all=false -> only READ ones (unread stay; the safe default
//
//	of the modal's "clear read"), all=true -> everything. One-shot reminders behind deleted
//	notifications are executed (dropped) first — same semantics as reading them.
//
// @complexity 4
// endregion FUNC_DeleteNotifications
func (s *Store) DeleteNotifications(ctx context.Context, all bool) (int64, error) {
	// Execute one-shot reminders behind the rows being deleted (best-effort, idempotent).
	var ids []int64
	sel := `SELECT id FROM notifications WHERE kind='reminder' AND ref_id IS NOT NULL`
	if !all {
		sel += ` AND read_at IS NOT NULL`
	}
	rows, err := s.DB.QueryContext(ctx, sel)
	if err == nil {
		for rows.Next() {
			var id int64
			if _ = rows.Scan(&id); true {
				ids = append(ids, id)
			}
		}
		rows.Close()
	}
	for _, id := range ids {
		_, _ = s.DeleteOneShotReminderForNotification(ctx, id)
	}
	q := `DELETE FROM notifications`
	if !all {
		q += ` WHERE read_at IS NOT NULL`
	}
	res, err := s.DB.ExecContext(ctx, q)
	if err != nil {
		return 0, fmt.Errorf("DeleteNotifications: %w", err)
	}
	n, _ := res.RowsAffected()
	logging.LDD(s.logger, 8, "DeleteNotifications", "DELETED", fmt.Sprintf("rows=%d all=%v", n, all))
	return n, nil
}
