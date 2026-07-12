// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Metrics; TECH(8): go test]
// @purpose Verify check_results repo: insert/list/retention round-trip in a tmp DB.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, check_results, insert, list, retention, repo
// STRUCTURE: ▶ ┌store┐ → ⊕ Insert×3 → ○ ListRecent(2) → ⚡ RetentionDelete(0d) → 〈assert〉
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestCheckResults_InsertListRetain(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "res.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	for i := 0; i < 3; i++ {
		if _, err := s.InsertCheckResult(ctx, 7, "ok", float64(10+i), "ok", map[string]any{"i": i}); err != nil {
			t.Fatalf("InsertCheckResult: %v", err)
		}
	}
	// ListRecent returns newest first, limited.
	got, err := s.ListRecentResults(ctx, 7, 2)
	if err != nil {
		t.Fatalf("ListRecentResults: %v", err)
	}
	if len(got) != 2 {
		t.Fatalf("want 2 results, got %d", len(got))
	}
	if got[0].Detail["i"].(float64) != 2 {
		t.Fatalf("newest first expected i=2, got %v", got[0].Detail)
	}
	if got[0].LatencyMS != 12 {
		t.Fatalf("latency round-trip failed: %v", got[0].LatencyMS)
	}

	// Retention: delete older than 0 days removes everything.
	n, err := s.RetentionDeleteResults(ctx, 0)
	if err != nil {
		t.Fatalf("RetentionDeleteResults: %v", err)
	}
	if n != 3 {
		t.Fatalf("retention want 3 deleted, got %d", n)
	}

	printIMPFromBuf(t, buf)
}
