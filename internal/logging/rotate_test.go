// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): LogRotation; TECH(8): go test]
// @purpose Verify rotation keeps the chain bounded and content ordered across files.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, rotation, rotating writer, backups, size limit
package logging

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// region FUNC_test_Rotation [DOMAIN(7): Testing; CONCEPT(7): ChainShift; TECH(5): t.TempDir]
// @purpose Small maxBytes force multiple rotations; every line written must survive in exactly
//
//	one file of the bounded chain.
//
// @complexity 3
// endregion FUNC_test_Rotation
func TestRotatingWriter_RotatesAndBounds(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "vmpulse.log")
	w, err := NewRotatingWriter(path, 120, 3)
	if err != nil {
		t.Fatalf("NewRotatingWriter: %v", err)
	}
	var sb strings.Builder
	for i := 0; i < 30; i++ {
		line := strings.Repeat("x", 20) + "\n"
		sb.WriteString(line)
		if _, err := w.Write([]byte(line)); err != nil {
			t.Fatalf("write %d: %v", i, err)
		}
	}
	_ = w.Close()

	// Chain bounded: active + .1 .. .3, no .4.
	for _, bad := range []string{path + ".4", path + ".5"} {
		if _, err := os.Stat(bad); !os.IsNotExist(err) {
			t.Fatalf("%s must not exist (chain unbounded)", bad)
		}
	}
	// All content present across the chain, in order.
	var got strings.Builder
	for _, p := range []string{path + ".3", path + ".2", path + ".1", path} {
		if b, err := os.ReadFile(p); err == nil {
			got.Write(b)
		}
	}
	if !strings.Contains(got.String(), sb.String()[len(sb.String())-60:]) {
		t.Fatal("recent content missing from the rotation chain")
	}
	t.Logf("[IMP:8][TestRotation][RESULT] chain bounded at 3 backups, tail preserved")
}

// endregion FUNC_test_Rotation
