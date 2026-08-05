// Package store — per-event domain reminders (list-based; multiple per domain/kind).
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(7]: DomainReminders; TECH(7]: database/sql]
// @purpose CRUD for domain_reminders: a domain may have several reminders per kind (e.g. cert at
//
//	30d and 7d), each with a channel and an optional repeat interval.
//
// @io List/Create/Delete + ListAllReminders (evaluator) + MarkReminderNotified (dedup)
// @invariants
//   - kind is validated to cert|owner|dns; dns ignores days.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: domain reminders, list, cert, owner, dns, repeat, channel, crud
// STRUCTURE: ▶ ┌DomainReminder┐ → ○ INSERT/SELECT/DELETE → ⎋
package store

import (
	"context"
	"database/sql"
	"fmt"

	"github.com/skibine/vm-pulse/internal/logging"
)

var validReminderKinds = map[string]bool{"cert": true, "owner": true, "dns": true}

// region FUNC_CreateDomainReminder [DOMAIN(7): Alerting; CONCEPT(6): Create; TECH(6): database/sql]
// @purpose Insert a reminder; validates kind + threshold.
// @complexity 4
// endregion FUNC_CreateDomainReminder
func (s *Store) CreateDomainReminder(ctx context.Context, r DomainReminder) (int64, error) {
	if !validReminderKinds[r.Kind] {
		return 0, fmt.Errorf("CreateDomainReminder: invalid kind %q", r.Kind)
	}
	if r.Kind != "dns" && r.Days <= 0 {
		return 0, fmt.Errorf("CreateDomainReminder: %s reminder needs days > 0", r.Kind)
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO domain_reminders (domain_id, kind, days, channel_id, repeat_days) VALUES (?,?,?,?,?)`,
		r.DomainID, r.Kind, r.Days, r.ChannelID, r.RepeatDays)
	if err != nil {
		logging.LDD(s.logger, 10, "CreateDomainReminder", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateDomainReminder: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// region FUNC_ListDomainReminders [DOMAIN(7): Alerting; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Return all reminders for one domain (for the UI list).
// @complexity 3
// endregion FUNC_ListDomainReminders
func (s *Store) ListDomainReminders(ctx context.Context, domainID int64) ([]DomainReminder, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, domain_id, kind, days, channel_id, repeat_days, COALESCE(last_notified_at,''), created_at
FROM domain_reminders WHERE domain_id=? ORDER BY kind, days ASC`, domainID)
	if err != nil {
		return nil, fmt.Errorf("ListDomainReminders: %w", err)
	}
	return scanReminders(rows, "ListDomainReminders")
}

// region FUNC_ListAllReminders [DOMAIN(7): Alerting; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Return every reminder (for the evaluator loop). Domain names are looked up separately.
// @complexity 4
// endregion FUNC_ListAllReminders
func (s *Store) ListAllReminders(ctx context.Context) ([]DomainReminder, error) {
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, domain_id, kind, days, channel_id, repeat_days, COALESCE(last_notified_at,''), created_at
FROM domain_reminders ORDER BY domain_id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListAllReminders: %w", err)
	}
	return scanReminders(rows, "ListAllReminders")
}

// scanReminders drains + closes the rows into a slice.
func scanReminders(rows *sql.Rows, label string) ([]DomainReminder, error) {
	defer rows.Close()
	var out []DomainReminder
	for rows.Next() {
		var r DomainReminder
		if err := rows.Scan(&r.ID, &r.DomainID, &r.Kind, &r.Days, &r.ChannelID, &r.RepeatDays, &r.LastNotified, &r.CreatedAt); err != nil {
			return nil, fmt.Errorf("%s scan: %w", label, err)
		}
		out = append(out, r)
	}
	return out, rows.Err()
}

// region FUNC_DeleteDomainReminder [DOMAIN(7): Alerting; CONCEPT(6): Delete; TECH(5): database/sql]
// @purpose Delete a single reminder by id.
// @complexity 2
// endregion FUNC_DeleteDomainReminder
func (s *Store) DeleteDomainReminder(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `DELETE FROM domain_reminders WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("DeleteDomainReminder: %w", err)
	}
	return nil
}

// region FUNC_MarkReminderNotified [DOMAIN(7): Alerting; CONCEPT(7): Dedup; TECH(5): database/sql]
// @purpose Stamp a reminder's last_notified_at so the dedup logic suppresses re-fire.
// @complexity 2
// endregion FUNC_MarkReminderNotified
func (s *Store) MarkReminderNotified(ctx context.Context, id int64) error {
	_, err := s.DB.ExecContext(ctx, `UPDATE domain_reminders SET last_notified_at=strftime('%Y-%m-%dT%H:%M:%fZ','now') WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("MarkReminderNotified: %w", err)
	}
	return nil
}
