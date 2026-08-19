// region FUNC_test_ReadDeletesOneShotReminder [DOMAIN(7): Testing; CONCEPT(8): Execute; TECH(6): database/sql]
// @purpose Reading a reminder notification "executes" it: the producing one-shot reminder (no repeat)
// @purpose is deleted, while a repeating reminder survives.
// @complexity 3
// endregion FUNC_test_ReadDeletesOneShotReminder
package store

import (
	"context"
	"log/slog"
	"os"
	"path/filepath"
	"testing"

	"github.com/skibine/vmp/internal/logging"
)

// reminderExists reports whether a reminder id is still present for the domain.
func reminderExists(t *testing.T, s *Store, domID, id int64) bool {
	t.Helper()
	rems, err := s.ListDomainReminders(context.Background(), domID)
	if err != nil {
		t.Fatalf("ListDomainReminders: %v", err)
	}
	for _, r := range rems {
		if r.ID == id {
			return true
		}
	}
	return false
}

func TestReadDeletesOneShotReminder(t *testing.T) {
	logger := logging.Setup(slog.LevelDebug, os.Stderr)
	s, err := Open(filepath.Join(t.TempDir(), "notif.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	domID, err := s.CreateDomain(ctx, Domain{Name: "ex.com"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	oneShotID, err := s.CreateDomainReminder(ctx, DomainReminder{DomainID: domID, Kind: "cert", Days: 30, RepeatDays: 0})
	if err != nil {
		t.Fatalf("CreateDomainReminder(one-shot): %v", err)
	}
	repeatID, err := s.CreateDomainReminder(ctx, DomainReminder{DomainID: domID, Kind: "cert", Days: 14, RepeatDays: 7})
	if err != nil {
		t.Fatalf("CreateDomainReminder(repeat): %v", err)
	}

	// In-app notification linked to the one-shot reminder (ref_id = reminder id).
	nid, err := s.CreateNotification(ctx, Notification{Title: "t", Body: "b", Kind: "reminder", RefID: &oneShotID})
	if err != nil {
		t.Fatalf("CreateNotification: %v", err)
	}

	if !reminderExists(t, s, domID, oneShotID) {
		t.Fatal("pre: one-shot reminder missing")
	}
	if !reminderExists(t, s, domID, repeatID) {
		t.Fatal("pre: repeating reminder missing")
	}

	if err := s.MarkNotificationRead(ctx, nid); err != nil {
		t.Fatalf("MarkNotificationRead: %v", err)
	}

	if reminderExists(t, s, domID, oneShotID) {
		t.Errorf("one-shot reminder NOT deleted after reading its notification")
	}
	if !reminderExists(t, s, domID, repeatID) {
		t.Errorf("repeating reminder wrongly deleted after reading")
	}
	t.Logf("[IMP:8][TestReadDeletes][RESULT] oneShotDeleted=%v repeatKept=%v", !reminderExists(t, s, domID, oneShotID), reminderExists(t, s, domID, repeatID))
}

func TestMarkAllDeletesOneShotReminders(t *testing.T) {
	logger := logging.Setup(slog.LevelDebug, os.Stderr)
	s, err := Open(filepath.Join(t.TempDir(), "notifall.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	domID, err := s.CreateDomain(ctx, Domain{Name: "ex2.com"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	o1, _ := s.CreateDomainReminder(ctx, DomainReminder{DomainID: domID, Kind: "owner", Days: 30, RepeatDays: 0})
	o2, _ := s.CreateDomainReminder(ctx, DomainReminder{DomainID: domID, Kind: "owner", Days: 7, RepeatDays: 0})
	r7, _ := s.CreateDomainReminder(ctx, DomainReminder{DomainID: domID, Kind: "cert", Days: 14, RepeatDays: 7})
	_, _ = s.CreateNotification(ctx, Notification{Title: "a", Body: "b", Kind: "reminder", RefID: &o1})
	_, _ = s.CreateNotification(ctx, Notification{Title: "c", Body: "d", Kind: "reminder", RefID: &o2})

	if err := s.MarkAllNotificationsRead(ctx); err != nil {
		t.Fatalf("MarkAllNotificationsRead: %v", err)
	}

	if reminderExists(t, s, domID, o1) || reminderExists(t, s, domID, o2) {
		t.Errorf("mark-all should delete one-shot reminders")
	}
	if !reminderExists(t, s, domID, r7) {
		t.Errorf("mark-all wrongly deleted the repeating reminder")
	}
	t.Logf("[IMP:8][TestMarkAll][RESULT] oneShotsDeleted=%v repeatKept=%v", !reminderExists(t, s, domID, o1) && !reminderExists(t, s, domID, o2), reminderExists(t, s, domID, r7))
}
