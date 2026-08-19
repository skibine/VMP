// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): API; TECH(8): go test,httptest]
// @purpose Verify /healthz: GET 200 with JSON status/db/schema_version; non-GET rejected.
//
//	Prints [IMP:7-10] lines (the [IMP:7] PROBE line is the Semantic Trace anchor).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, api, healthz, httptest, liveness
// STRUCTURE: ▶ ┌store┐ → ○ New → ⚡ httptest GET /healthz → 〈200? status=ok? db?〉 → ⎋ assert
package api

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skibine/vmp/internal/lddcheck"
	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
)

func newServer(t *testing.T) (*Server, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	dbPath := filepath.Join(t.TempDir(), "api.sqlite")
	s, err := store.Open(dbPath, logger)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	return New(s, "127.0.0.1:0", logger), &buf
}

func printIMPFromBuf(t *testing.T, buf *bytes.Buffer) {
	t.Helper()
	out := buf.String()
	t.Log("--- LDD TRAJECTORY (IMP:7-10) ---")
	for _, line := range strings.Split(out, "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 7 {
			t.Log(line)
		}
	}
}

func TestHealthz_OK(t *testing.T) {
	srv, buf := newServer(t)
	req := httptest.NewRequest(http.MethodGet, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	printIMPFromBuf(t, buf)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", rec.Code)
	}
	var body map[string]any
	if err := json.NewDecoder(rec.Body).Decode(&body); err != nil {
		t.Fatalf("decode: %v", err)
	}
	if body["status"] != "ok" {
		t.Fatalf("expected status=ok, got %v", body["status"])
	}
	if body["db"] != true {
		t.Fatalf("expected db=true, got %v", body["db"])
	}
	if v, ok := body["schema_version"].(float64); !ok || v < 1 {
		t.Fatalf("expected schema_version>=1, got %v", body["schema_version"])
	}
}

func TestHealthz_MethodNotAllowed(t *testing.T) {
	srv, _ := newServer(t)
	req := httptest.NewRequest(http.MethodPost, "/healthz", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusMethodNotAllowed {
		t.Fatalf("expected 405, got %d", rec.Code)
	}
}
