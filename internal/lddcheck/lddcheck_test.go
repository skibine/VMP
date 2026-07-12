// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7): Parse; TECH(8): go test]
// @purpose Verify lddcheck.IMPValue handles single/double digit IMP and rejects malformed.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, lddcheck, IMP, parse
// STRUCTURE: ▶ ┌cases┐ → ○ IMPValue → 〈want==got?〉 → ⎋ assert
package lddcheck

import "testing"

func TestIMPValue(t *testing.T) {
	cases := []struct {
		line string
		want int
		ok   bool
	}{
		{`level=INFO msg="[IMP:9][Open][MIGRATED] applied 1"`, 9, true},
		{`[IMP:10][main][START] vmpulse starting`, 10, true},
		{`[IMP:3][x][y] trace`, 3, true},
		{"no imp here", 0, false},
		{`[IMP:] bad`, 0, false},
		{`[IMP:abc] bad`, 0, false},
	}
	for _, c := range cases {
		got, ok := IMPValue(c.line)
		if got != c.want || ok != c.ok {
			t.Errorf("IMPValue(%q) = (%d,%v), want (%d,%v)", c.line, got, ok, c.want, c.ok)
		}
	}
}
