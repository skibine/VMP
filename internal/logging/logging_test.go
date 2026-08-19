// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): Telemetry; TECH(8): go test]
// @purpose Verify the LDD helper emits the canonical [IMP:N] token + imp attribute and that
//
//	Setup never returns nil. Prints [IMP:7-10] lines (Semantic Trace Verification).
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, logging, LDD, IMP, telemetry
// STRUCTURE: ▶ ┌buf┐ → ○ LDD(imp=9) → 〈grep [IMP:9] + imp=9〉 → ⎋ assert
package logging

import (
	"bytes"
	"log/slog"
	"strings"
	"testing"

	"github.com/skibine/vmp/internal/lddcheck"
)

// printIMP prints LDD lines with IMP>=7 to the test console (Semantic Trace Verification).
func printIMP(t *testing.T, out string) {
	t.Helper()
	t.Log("--- LDD TRAJECTORY (IMP:7-10) ---")
	for _, line := range strings.Split(out, "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 7 {
			t.Log(line)
		}
	}
}

func TestSetup_NonNil(t *testing.T) {
	l := Setup(slog.LevelInfo)
	if l == nil {
		t.Fatal("Setup returned nil logger")
	}
}

func TestLDD_EmitsCanonicalTokenAndAttr(t *testing.T) {
	var buf bytes.Buffer
	logger := Setup(slog.LevelDebug, &buf)
	LDD(logger, 9, "Open", "MIGRATED", "applied 1 migrations")
	out := buf.String()
	printIMP(t, out)
	if !strings.Contains(out, "[IMP:9][Open][MIGRATED] applied 1 migrations") {
		t.Fatalf("missing canonical LDD line:\n%s", out)
	}
	if !strings.Contains(out, "imp=9") {
		t.Fatalf("missing imp=9 attribute:\n%s", out)
	}
}

func TestLDD_NilLoggerIsNoOp(t *testing.T) {
	// Must not panic.
	LDD(nil, 9, "fn", "blk", "noop")
}
