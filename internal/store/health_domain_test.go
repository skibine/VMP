// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): HealthReadModel; TECH(8): go test]
// @purpose Verify LatestResultsForDomain: one row per domain check, with/without a result row.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, LatestResultsForDomain, domain checks, read model
package store

import (
	"context"
	"path/filepath"
	"testing"
)

func TestLatestResultsForDomain_WithAndWithoutResults(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "hd.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	domID, err := s.CreateDomain(ctx, Domain{Name: "example.com"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	if err := s.EnsureDomainChecks(ctx, domID); err != nil {
		t.Fatalf("EnsureDomainChecks: %v", err)
	}
	// Only the whois check gets a result; tls stays result-less.
	var whoisCheck int64
	rows0, _ := s.ListChecks(ctx, nil)
	for _, c := range rows0 {
		if c.DomainID != nil && *c.DomainID == domID && c.CheckType == "whois" {
			whoisCheck = c.ID
		}
	}
	if whoisCheck == 0 {
		t.Fatalf("no whois check provisioned for the domain")
	}
	_, _ = s.InsertCheckResult(ctx, whoisCheck, "ok", 3.0, "60 days left", nil)

	rows, err := s.LatestResultsForDomain(ctx, domID)
	if err != nil {
		t.Fatalf("LatestResultsForDomain: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("want 2 rows (whois+tls), got %d", len(rows))
	}
	byType := map[string]VMCheckStatus{}
	for _, r := range rows {
		byType[r.CheckType] = r
	}
	if byType["whois"].LatestStatus != "ok" || byType["whois"].LatestMessage != "60 days left" {
		t.Fatalf("whois latest mismatch: %+v", byType["whois"])
	}
	if byType["tls"].LatestStatus != "" {
		t.Fatalf("tls should have empty status (no run yet), got %q", byType["tls"].LatestStatus)
	}

	// Unknown domain -> empty slice (must not return VM checks).
	rows, _ = s.LatestResultsForDomain(ctx, 9999)
	if len(rows) != 0 {
		t.Fatalf("unknown domain want 0 rows, got %d", len(rows))
	}

	printIMPFromBuf(t, buf)
}
