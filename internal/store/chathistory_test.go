// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): SharedChatHistory; TECH(8): go test]
// @purpose Verify the shared chat history store: append+read order, trim to cap, clear.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, chat history, append turn, list, trim, clear
package store

import (
	"context"
	"path/filepath"
	"strconv"
	"testing"
)

func TestChatHistory_AppendListClear(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "chh.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// Two turns; the second must see the first in chronological order.
	if err := s.AppendChatTurn(ctx, "что с web1?", "работает"); err != nil {
		t.Fatalf("AppendChatTurn: %v", err)
	}
	if err := s.AppendChatTurn(ctx, "а домены?", "3 шт"); err != nil {
		t.Fatalf("AppendChatTurn 2: %v", err)
	}
	msgs, err := s.ListChatMessages(ctx, 50)
	if err != nil {
		t.Fatalf("ListChatMessages: %v", err)
	}
	if len(msgs) != 4 {
		t.Fatalf("want 4 messages, got %d", len(msgs))
	}
	want := []struct{ role, content string }{
		{"user", "что с web1?"}, {"assistant", "работает"},
		{"user", "а домены?"}, {"assistant", "3 шт"},
	}
	for i, w := range want {
		if msgs[i].Role != w.role || msgs[i].Content != w.content {
			t.Fatalf("msg %d = %+v, want %v", i, msgs[i], w)
		}
	}

	// limit returns only the newest, still chronologically.
	tail, _ := s.ListChatMessages(ctx, 2)
	if len(tail) != 2 || tail[0].Content != "а домены?" || tail[1].Content != "3 шт" {
		t.Fatalf("tail mismatch: %+v", tail)
	}

	// Clear empties the thread.
	if err := s.ClearChatMessages(ctx); err != nil {
		t.Fatalf("ClearChatMessages: %v", err)
	}
	after, _ := s.ListChatMessages(ctx, 50)
	if len(after) != 0 {
		t.Fatalf("want empty after clear, got %d", len(after))
	}
	t.Logf("[IMP:8][TestChatHistory][RESULT] append=4 tail=2 clear=0")
	printIMPFromBuf(t, buf)
}

func TestChatHistory_TrimToCap(t *testing.T) {
	log, _ := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "chh2.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// 150 turns = 300 rows > cap 200 → only newest 200 survive.
	for i := 0; i < 150; i++ {
		if err := s.AppendChatTurn(ctx, "q"+strconv.Itoa(i), "a"+strconv.Itoa(i)); err != nil {
			t.Fatalf("turn %d: %v", i, err)
		}
	}
	msgs, _ := s.ListChatMessages(ctx, 1000)
	if len(msgs) != 200 {
		t.Fatalf("want 200 rows after trim, got %d", len(msgs))
	}
	// Newest message is the last assistant answer.
	if msgs[len(msgs)-1].Role != "assistant" || msgs[len(msgs)-1].Content != "a149" {
		t.Fatalf("newest mismatch: %+v", msgs[len(msgs)-1])
	}
	t.Logf("[IMP:8][TestChatHistory][TRIM] rows=%d newest=a149", len(msgs))
}
