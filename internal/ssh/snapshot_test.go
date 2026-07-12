// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): SnapshotParse; TECH(8): go test,regex]
// @purpose Verify tolerant parsing of a realistic free/df/uptime/loadavg/nproc dump, plus graceful
//
//	behavior when a section is missing.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, snapshot, parse, free, df, uptime, loadavg, nproc, tolerant
package ssh

import (
	"strings"
	"testing"
)

const sampleSnapshot = "=mem=\n" +
	"               total        used        free      shared  buff/cache   available\n" +
	"Mem:           1987        1023         234          45         729         654\n" +
	"Swap:          1024           0        1024\n" +
	"=df=\n" +
	"Filesystem      Size  Used Avail Use% Mounted on\n" +
	"/dev/sda1        40G   25G   13G  67% /\n" +
	"=up=\n" +
	" 12:30:01 up 10 days,  3:42,  2 users,  load average: 0.10, 0.05, 0.01\n" +
	"=load=\n" +
	"0.10 0.05 0.01 1/123 4567\n" +
	"=cpu=\n" +
	"4\n"

func TestParseSnapshot_Realistic(t *testing.T) {
	s := parseSnapshot(sampleSnapshot)
	if s.MemTotalMB != 1987 || s.MemUsedMB != 1023 {
		t.Errorf("mem: got %d/%d, want 1023/1987", s.MemUsedMB, s.MemTotalMB)
	}
	if s.DiskTotalGB != 40 || s.DiskUsedGB != 25 {
		t.Errorf("disk: got %.1f/%.1f, want 25/40", s.DiskUsedGB, s.DiskTotalGB)
	}
	if s.Load1 != 0.10 || s.Load5 != 0.05 || s.Load15 != 0.01 {
		t.Errorf("load: got %.3f/%.3f/%.3f, want 0.10/0.05/0.01", s.Load1, s.Load5, s.Load15)
	}
	if s.CPUCount != 4 {
		t.Errorf("cpu: got %d, want 4", s.CPUCount)
	}
	if !strings.HasPrefix(s.Uptime, "10 days") {
		t.Errorf("uptime: got %q, want start with '10 days'", s.Uptime)
	}
}

func TestParseSnapshot_Units(t *testing.T) {
	// terabyte disk => 2T == 2048 GB
	df := "=df=\nFilesystem Size Used Avail Use% Mounted on\n/dev/x 2T 1T 1T 50% /\n=cpu=\n8\n"
	s := parseSnapshot(df)
	if s.DiskTotalGB != 2048 || s.DiskUsedGB != 1024 {
		t.Errorf("T-unit disk: got %.0f/%.0f, want 1024/2048", s.DiskUsedGB, s.DiskTotalGB)
	}
	if s.CPUCount != 8 {
		t.Errorf("cpu: got %d, want 8", s.CPUCount)
	}
}

func TestParseSnapshot_MissingSections(t *testing.T) {
	// only mem present; rest must be zero without error
	s := parseSnapshot("=mem=\nMem: 500 250 250\n")
	if s.MemTotalMB != 500 || s.MemUsedMB != 250 {
		t.Errorf("mem: got %d/%d, want 250/500", s.MemUsedMB, s.MemTotalMB)
	}
	if s.DiskTotalGB != 0 || s.Load1 != 0 || s.CPUCount != 0 || s.Uptime != "" {
		t.Errorf("expected zero/empty for missing sections, got %+v", s)
	}
}
