// Package lddcheck parses LDD log lines for Semantic Trace Verification.
//
// region MODULE_CONTRACT [DOMAIN(9): Observability; CONCEPT(8): LDDParse; TECH(6): strings]
// @purpose Extract the IMP importance value from a log line of the form "...[IMP:N]..." so
//
//	tests and tools can filter/verify the AI-belief trajectory without fragile slicing.
//
// @io line string -> (int, bool)
// @invariants
//   - IMPValue returns (value, true) only for a well-formed [IMP:N] token with N>=0.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: LDD, IMP, parse, trace, verify, telemetry, filter
// STRUCTURE: ▶ ┌line┐ → ○ find "[IMP:" → ○ read until ']' → ⊕ atoi → ⎷ (n,true)
package lddcheck

import "strings"

const mark = "[IMP:"

// IMPValue extracts the importance integer from the first [IMP:N] token in line.
// Returns (0,false) when no token is present or it is malformed.
func IMPValue(line string) (int, bool) {
	i := strings.Index(line, mark)
	if i < 0 {
		return 0, false
	}
	tail := line[i+len(mark):]
	j := strings.IndexByte(tail, ']')
	if j <= 0 {
		return 0, false
	}
	n := 0
	for k := 0; k < j; k++ {
		c := tail[k]
		if c < '0' || c > '9' {
			return 0, false
		}
		n = n*10 + int(c-'0')
	}
	return n, true
}
