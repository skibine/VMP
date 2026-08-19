// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): Config; TECH(8): go test]
// @purpose Verify config loading: missing file -> safe defaults; invalid mode -> local;
//
//	valid YAML -> typed Config. Prints [IMP:7-10] lines.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, config, mode, local, server, defaults, yaml
// STRUCTURE: ▶ ┌path┐ → ○ Load → 〈missing? Default : normalized〉 → ⎋ assert Mode/Listen
package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"bytes"
	"github.com/skibine/vmp/internal/lddcheck"
	"github.com/skibine/vmp/internal/logging"
	"log/slog"
)

func testLogger(t *testing.T) (*slog.Logger, *bytes.Buffer) {
	t.Helper()
	var buf bytes.Buffer
	return logging.Setup(slog.LevelDebug, &buf), &buf
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

func TestLoad_MissingFile_ReturnsDefault(t *testing.T) {
	log, buf := testLogger(t)
	cfg, err := Load(filepath.Join(t.TempDir(), "nope.yaml"), log)
	if err != nil {
		t.Fatalf("expected nil error on missing file, got %v", err)
	}
	printIMPFromBuf(t, buf)
	if cfg.Mode != ModeLocal {
		t.Fatalf("expected default mode=local, got %q", cfg.Mode)
	}
	if !strings.HasPrefix(cfg.Listen, "127.0.0.1") {
		t.Fatalf("expected localhost default bind, got %q", cfg.Listen)
	}
}

func TestLoad_BadMode_NormalizedToLocal(t *testing.T) {
	log, buf := testLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(path, []byte("mode: hyperserver\nlisten: 0.0.0.0:9000\ndb_path: d/x.sqlite\nlog_level: warn\n"), 0o600)
	cfg, err := Load(path, log)
	if err != nil {
		t.Fatal(err)
	}
	printIMPFromBuf(t, buf)
	if cfg.Mode != ModeLocal {
		t.Fatalf("bad mode should collapse to local, got %q", cfg.Mode)
	}
}

func TestLoad_ValidServer(t *testing.T) {
	log, buf := testLogger(t)
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	_ = os.WriteFile(path, []byte("mode: server\nlisten: 0.0.0.0:8443\ndb_path: d/x.sqlite\n"), 0o600)
	cfg, err := Load(path, log)
	if err != nil {
		t.Fatal(err)
	}
	printIMPFromBuf(t, buf)
	if !cfg.IsServer() {
		t.Fatalf("expected server mode")
	}
}
