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
	"4\n" +
	"=cstat1=\ncpu  100 0 100 800 0 0 0 0\n" +
	"=cstat2=\ncpu  100 0 100 850 0 0 0 0\n" +
	"=tcp=\n3\n"

func TestCPUPctFromStat(t *testing.T) {
	// total1=1000 (idle 800, busy 200); total2=1100 (idle 850, busy 250) -> busyDelta 50 / totalDelta 100 = 50%.
	l1 := "cpu  100 0 100 800 0 0 0 0"
	l2 := "cpu  100 0 100 850 0 0 0 0"
	// recompute: busy = total-idle; t1: 1000-800=200; t2: 1050-850=200 -> 0%. Build a 50% pair instead:
	l1 = "cpu  100 0 100 800 0" // total 1000 idle 800 busy 200
	l2 = "cpu  150 0 100 850 0" // total 1100 idle 850 busy 250 -> 50/100 = 50%
	pct := cpuPctFromStat(l1, l2)
	if pct < 49.9 || pct > 50.1 {
		t.Fatalf("cpu pct: got %.2f, want ~50", pct)
	}
	if cpuPctFromStat("", l2) != 0 {
		t.Fatal("missing cstat1 should yield 0")
	}
}

func TestSplitSections_EmptyMiddle(t *testing.T) {
	// An empty section (docker) must NOT swallow the following marker (regression guard).
	out := "=a=\nfoo\n=docker=\n=pkgs=\n365\n=svc=\n21\n"
	sec := splitSections(out)
	if sec["a"] != "foo" {
		t.Errorf("a: %q", sec["a"])
	}
	if sec["docker"] != "" {
		t.Errorf("empty docker must be '', got %q", sec["docker"])
	}
	if sec["pkgs"] != "365" || sec["svc"] != "21" {
		t.Errorf("pkgs/svc after empty section: %q/%q", sec["pkgs"], sec["svc"])
	}
}

func TestNetFromProcDev(t *testing.T) {
	dev := "Inter-|   Receive ...\n face |bytes ...\n" +
		"    lo: 1000 10 0 0 0 0 0 0 1000 10 0 0 0 0 0 0\n" +
		"  eth0: 500000 100 0 0 0 0 0 0 200000 80 0 0 0 0 0 0\n" +
		"  eth1:    10   1 0 0 0 0 0 0     5   1 0 0 0 0 0 0\n"
	iface, rx, tx := netFromProcDev(dev)
	if iface != "eth0" || rx != 500000 || tx != 200000 {
		t.Errorf("busiest iface: %s rx=%d tx=%d, want eth0/500000/200000", iface, rx, tx)
	}
}

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
	// cstat1 total=1000 idle=800; cstat2 total=1050 idle=850 -> busy delta=0 -> 0%? recompute:
	// total1=100+0+100+800=1000, idle1=800(+0)=800; total2=100+0+100+850=1050, idle2=850;
	// busyDelta=((1050-850)-(1000-800))=(200-200)=0 -> 0.0%. Use a sample with actual busy growth:
	if s.TCPConns != 3 {
		t.Errorf("tcp conns: got %d, want 3", s.TCPConns)
	}
	if s.ProcCount != 123 {
		t.Errorf("proc count: got %d, want 123", s.ProcCount)
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
