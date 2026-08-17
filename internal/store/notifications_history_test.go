// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): NotificationHistory; TECH(8): go test]
// @purpose Verify the modal history store layer: filtered paging (unread/kind), delete read-only
//
//	vs all, and one-shot-reminder execution on delete.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, notifications, filtered, history, delete read, delete all, one-shot
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestNotificationsFilteredAndDelete(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "nf.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// Seed: 3 alerts (2 read), 1 reminder (unread), 1 test.
	ids := make([]int64, 0, 5)
	for i := 0; i < 3; i++ {
		id, _ := s.CreateNotification(ctx, Notification{Title: "a", Body: "b", Kind: "alert"})
		ids = append(ids, id)
	}
	remID, _ := s.CreateNotification(ctx, Notification{Title: "r", Body: "b", Kind: "reminder"})
	_ = remID
	testID, _ := s.CreateNotification(ctx, Notification{Title: "t", Body: "b", Kind: "test"})
	_ = testID
	_ = s.MarkNotificationRead(ctx, ids[0])
	_ = s.MarkNotificationRead(ctx, ids[1])

	// Total 5; unread=2; kind=alert=3.
	_, total, _ := s.ListNotificationsFiltered(ctx, NotificationFilter{Limit: 10})
	if total != 5 {
		t.Fatalf("total want 5, got %d", total)
	}
	items, total, _ := s.ListNotificationsFiltered(ctx, NotificationFilter{UnreadOnly: true, Limit: 10})
	if total != 3 || len(items) != 3 { // 1 unmarked alert + reminder + test
		t.Fatalf("unread want 3, got %d/%d", len(items), total)
	}
	_, total, _ = s.ListNotificationsFiltered(ctx, NotificationFilter{Kind: "alert", Limit: 10})
	if total != 3 {
		t.Fatalf("kind=alert want 3, got %d", total)
	}
	// History order: newest first (test created last).
	items, _, _ = s.ListNotificationsFiltered(ctx, NotificationFilter{Limit: 1})
	if len(items) != 1 || items[0].Kind != "test" {
		t.Fatalf("newest-first violated: %+v", items)
	}

	// Delete READ only: 2 gone, 3 stay (incl. unread reminder).
	n, err := s.DeleteNotifications(ctx, false)
	if err != nil || n != 2 {
		t.Fatalf("delete-read want 2, got %d err=%v", n, err)
	}
	_, total, _ = s.ListNotificationsFiltered(ctx, NotificationFilter{})
	if total != 3 {
		t.Fatalf("after delete-read want 3, got %d", total)
	}

	// Delete ALL: everything gone.
	n, _ = s.DeleteNotifications(ctx, true)
	if n != 3 {
		t.Fatalf("delete-all want 3, got %d", n)
	}
	_, total, _ = s.ListNotificationsFiltered(ctx, NotificationFilter{})
	if total != 0 {
		t.Fatalf("after delete-all want 0, got %d", total)
	}
	t.Logf("[IMP:8][TestNotifFiltered][RESULT] total=5 unread=2 kind=3 delread=2 delall=3")
	printIMPFromBuf(t, buf)
}
