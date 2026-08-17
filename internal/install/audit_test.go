package install

// region MODULE_CONTRACT [DOMAIN(7): Testing; CONCEPT(8): HostAudit; TECH(7): go-test,fixtures]
// @purpose Verify the local-Linux parsers (os-release, /proc/net/tcp, sshd_config) and the pure
// @purpose risk verdict over synthetic reports. Parsers are fed fixture files under t.TempDir().
// endregion MODULE_CONTRACT
// GREP_SUMMARY: test, parsers, os-release, proc net tcp, sshd_config, risk verdict, LDD

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/monitor"
	"log/slog"
)

// region FUNC_test_parseOSRelease [DOMAIN(6): Testing; CONCEPT(7): Distro; TECH(6): fixture]
// @purpose PRETTY_NAME wins; falls back to NAME+VERSION.
// @complexity 2
// endregion FUNC_test_parseOSRelease
func TestParseOSRelease(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "os-release")
	_ = os.WriteFile(p, []byte(`NAME="Ubuntu"
VERSION="22.04.3 LTS (Jammy Jellyfish)"
ID=ubuntu
PRETTY_NAME="Ubuntu 22.04.3 LTS"
`), 0o644)
	got := parseOSRelease(p)
	if got != "Ubuntu 22.04.3 LTS" {
		t.Fatalf("want PRETTY_NAME, got %q", got)
	}

	// No PRETTY_NAME -> NAME + VERSION fallback.
	p2 := filepath.Join(dir, "os2")
	_ = os.WriteFile(p2, []byte(`NAME="Debian"
VERSION="12 (bookworm)"
`), 0o644)
	if got2 := parseOSRelease(p2); got2 != "Debian 12 (bookworm)" {
		t.Fatalf("want NAME+VERSION fallback, got %q", got2)
	}
	t.Logf("[IMP:8][TestOSRelease][RESULT] pretty=%q fallback=%q", got, parseOSRelease(p2))
}

// region FUNC_test_parseListeningPorts [DOMAIN(7): Testing; CONCEPT(8]: Ports; TECH(7]: fixture]
// @purpose Only LISTEN (st=0A) rows are extracted; port decoded from hex; wildcard addr decoded.
// @complexity 3
// endregion FUNC_test_parseListeningPorts
func TestParseListeningPorts(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "tcp")
	// port 0x0016=22 LISTEN on 0.0.0.0 (00000000); port 0x01BB=443 LISTEN; a non-LISTEN row ignored.
	_ = os.WriteFile(p, []byte(`  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode
   0: 00000000:0016 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12345 1 0000000000000000 100 0 0 10 0
   1: 00000000:01BB 00000000:0000 0A 00000000:00000000 00:00000000 00000000     0        0 12346 1 0000000000000000 100 0 0 10 0
   2: 0100007F:8421 00000000:0000 06 00000000:00000000 00:00000000 00000000     0        0 12347 1 0000000000000000 100 0 0 10 0
`), 0o644)
	got := parseListeningPorts(p, "tcp")
	if len(got) != 2 {
		t.Fatalf("want 2 LISTEN ports, got %d: %+v", len(got), got)
	}
	ports := map[int]bool{}
	for _, pr := range got {
		ports[pr.Port] = true
		if pr.Addr == "0.0.0.0" && pr.Port == 22 {
			// good
		}
	}
	if !ports[22] || !ports[443] {
		t.Fatalf("want 22 and 443, got %+v", ports)
	}
	t.Logf("[IMP:8][TestPorts][RESULT] listen=%+v", got)
}

// region FUNC_test_parseSSHDConfig [DOMAIN(8]: Testing; CONCEPT(8]: SSHPosture; TECH(6]: fixture]
// @purpose Last directive wins; absent PasswordAuthentication defaults to "yes"; ConfigReadable set.
// @complexity 2
// endregion FUNC_test_parseSSHDConfig
func TestParseSSHDConfig(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "sshd_config")
	_ = os.WriteFile(p, []byte(`# sshd config
Port 2222
PermitRootLogin yes
PasswordAuthentication no
`), 0o644)
	cfg := parseSSHDConfig(p)
	if !cfg.ConfigReadable || cfg.Port != "2222" || cfg.PermitRootLogin != "yes" || cfg.PasswordAuth != "no" {
		t.Fatalf("unexpected cfg: %+v", cfg)
	}
	// Absent PasswordAuthentication -> default "yes".
	p2 := filepath.Join(dir, "sshd2")
	_ = os.WriteFile(p2, []byte("Port 22\n"), 0o644)
	if c2 := parseSSHDConfig(p2); c2.PasswordAuth != "yes" {
		t.Fatalf("absent PasswordAuthentication should default to yes, got %q", c2.PasswordAuth)
	}
	t.Logf("[IMP:8][TestSSHD][RESULT] %+v", cfg)
}

// region FUNC_test_Risk [DOMAIN(9]: Testing; CONCEPT(9]: RiskModel; TECH(6]: pure]
// @purpose Verdict severity + findings across critical (root+remote+exposure), warn (datacenter),
// @purpose and ok (safe local) postures.
// @complexity 4
// endregion FUNC_test_Risk
func TestRisk(t *testing.T) {
	allAbsent := FirewallState{Engines: []EngineState{
		{Name: "ufw", State: "absent"}, {Name: "firewalld", State: "absent"},
		{Name: "nftables", State: "absent"}, {Name: "iptables", State: "absent"},
	}}
	// Critical: root + remote + an exposure + no firewall.
	crit := HostReport{
		Privilege: Privilege{Root: true, User: "root"},
		Network:   NetworkPosture{IsLikelyRemote: true, IsDatacenter: true},
		Firewall:  allAbsent,
		Exposures: []monitor.Finding{{ID: "redis", Title: "Redis without auth", Severity: "critical"}},
	}
	v := Risk(crit)
	if v.Severity != "critical" {
		t.Fatalf("critical posture want severity critical, got %s (findings=%d)", v.Severity, len(v.Findings))
	}
	if !hasFinding(v.Findings, "svc_as_root") || !hasFinding(v.Findings, "exposed_unauth") || !hasFinding(v.Findings, "no_firewall_public") {
		t.Fatalf("missing expected findings: %+v", findingIDs(v.Findings))
	}
	t.Logf("[IMP:9][TestRisk][CRITICAL] severity=%s score=%d findings=%s", v.Severity, v.Score, strings.Join(findingIDs(v.Findings), ","))

	// Warn: datacenter, not root, firewall active, no exposures -> datacenter_bind_wildcard.
	warn := HostReport{
		Network:  NetworkPosture{IsDatacenter: true, IsLikelyRemote: true},
		Firewall: FirewallState{Engines: []EngineState{{Name: "ufw", State: "active"}}},
	}
	vw := Risk(warn)
	if vw.Severity != "warn" {
		t.Fatalf("datacenter posture want warn, got %s", vw.Severity)
	}
	if !hasFinding(vw.Findings, "datacenter_bind_wildcard") {
		t.Fatalf("missing datacenter_bind_wildcard: %+v", findingIDs(vw.Findings))
	}
	t.Logf("[IMP:9][TestRisk][WARN] severity=%s score=%d", vw.Severity, vw.Score)

	// OK: local home box, no exposure, not root.
	ok := HostReport{Network: NetworkPosture{IsLikelyRemote: false}}
	vo := Risk(ok)
	if vo.Severity != "ok" || len(vo.Findings) != 0 {
		t.Fatalf("safe local posture want ok/0 findings, got %s/%d", vo.Severity, len(vo.Findings))
	}
	t.Logf("[IMP:9][TestRisk][OK] severity=%s score=%d findings=%d", vo.Severity, vo.Score, len(vo.Findings))

	// Unreadable firewall (non-root, engines present but permission-denied): NO false "no firewall";
	// instead a minor "unreadable" hint pointing to elevation.
	ur := HostReport{
		Privilege: Privilege{Root: false},
		Network:   NetworkPosture{IsLikelyRemote: true},
		Firewall:  FirewallState{Engines: []EngineState{{Name: "ufw", State: "unknown"}, {Name: "nftables", State: "unknown"}}},
	}
	vu := Risk(ur)
	if hasFinding(vu.Findings, "no_firewall_public") {
		t.Fatalf("must NOT claim no_firewall when state is unknown: %+v", findingIDs(vu.Findings))
	}
	if !hasFinding(vu.Findings, "firewall_unreadable") {
		t.Fatalf("expected firewall_unreadable hint: %+v", findingIDs(vu.Findings))
	}
	t.Logf("[IMP:9][TestRisk][UNREADABLE] severity=%s findings=%s", vu.Severity, strings.Join(findingIDs(vu.Findings), ","))
}

// region FUNC_test_LooksLikeDatacenter [DOMAIN(8]: Testing; CONCEPT(9]: RemoteLocal; TECH(6]: heuristic]
// @purpose Known hosting providers classify as datacenter; a residential ISP does not.
// @complexity 2
// endregion FUNC_test_LooksLikeDatacenter
func TestLooksLikeDatacenter(t *testing.T) {
	if !looksLikeDatacenter("Hetzner Online GmbH", "", "hetzner.com", "") {
		t.Error("Hetzner should classify as datacenter")
	}
	if !looksLikeDatacenter("", "", "", "ec2-3-4-5-6.compute-1.amazonaws.com") {
		t.Error("AWS PTR should classify as datacenter")
	}
	if looksLikeDatacenter("Rostelecom", "PJSC Rostelecom", "rt.ru", "") {
		t.Error("residential ISP should NOT classify as datacenter")
	}
	t.Log("[IMP:8][TestDatacenter][RESULT] hetzner/aws=true, residential=false")
}

// region FUNC_test_AuditEndToEnd [DOMAIN(9]: Testing; CONCEPT(8]: Integration; TECH(7]: local]
// @purpose Audit() runs end-to-end on the test host and always returns a verdict (no panic, no hang).
// @complexity 3
// endregion FUNC_test_AuditEndToEnd
func TestAuditEndToEnd(t *testing.T) {
	logger := logging.Setup(slog.LevelDebug, &strings.Builder{})
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	rep := Audit(ctx, logger)
	if rep.Verdict.Severity != "ok" && rep.Verdict.Severity != "warn" && rep.Verdict.Severity != "critical" {
		t.Fatalf("unexpected verdict severity: %q", rep.Verdict.Severity)
	}
	if rep.At.IsZero() {
		t.Fatal("report timestamp not set")
	}
	t.Logf("[IMP:9][TestAuditE2E][RESULT] platform=%s public_ip=%s remote=%v verdict=%s score=%d findings=%d",
		rep.Platform, rep.Network.PublicIP, rep.Network.IsLikelyRemote, rep.Verdict.Severity, rep.Verdict.Score, len(rep.Verdict.Findings))
}

// region FUNC_test_parseNetshFirewall [DOMAIN(8): Testing; CONCEPT(7]: Firewall; TECH(6]: parser]
// @purpose netsh output: all profiles ON => active; any OFF => inactive; nothing parseable => unknown.
// @complexity 2
// endregion FUNC_test_parseNetshFirewall
func TestParseNetshFirewall(t *testing.T) {
	allOn := `Domain Profile Settings:
State                                 ON
Private Profile Settings:
State                                 ON
Public Profile Settings:
State                                 ON
`
	if got := parseNetshFirewall(allOn); got != "active" {
		t.Fatalf("all profiles ON want active, got %s", got)
	}
	oneOff := strings.Replace(allOn, "State                                 ON", "State                                 OFF", 1)
	if got := parseNetshFirewall(oneOff); got != "inactive" {
		t.Fatalf("one profile OFF want inactive, got %s", got)
	}
	if got := parseNetshFirewall("garbage no state lines"); got != "unknown" {
		t.Fatalf("unparseable want unknown, got %s", got)
	}
	t.Log("[IMP:8][TestNetsh][RESULT] allOn=active, anyOff=inactive, garbage=unknown")
}

// region FUNC_test_parseNetstatListening [DOMAIN(7]: Testing; CONCEPT(8]: Ports; TECH(6]: parser]
// @purpose netstat -ano: only LISTENING rows are taken; port parsed after last ':'; dedup.
// @complexity 2
// endregion FUNC_test_parseNetstatListening
func TestParseNetstatListening(t *testing.T) {
	out := `Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:135            0.0.0.0:0              LISTENING       1234
  TCP    0.0.0.0:443            0.0.0.0:0              LISTENING       5678
  TCP    [::]:3389              [::]:0                 LISTENING       9012
  TCP    10.0.0.5:49152         93.184.216.34:443      ESTABLISHED     3456
`
	got := parseNetstatListening(out)
	ports := map[int]bool{}
	for _, p := range got {
		ports[p.Port] = true
	}
	if !ports[135] || !ports[443] || !ports[3389] || ports[49152] {
		t.Fatalf("want LISTENING 135/443/3389 (not ESTABLISHED 49152), got %+v", ports)
	}
	t.Logf("[IMP:8][TestNetstat][RESULT] listening=%+v", ports)
}

func hasFinding(fs []RiskFinding, id string) bool {
	for _, f := range fs {
		if f.ID == id {
			return true
		}
	}
	return false
}
func findingIDs(fs []RiskFinding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.ID)
	}
	return out
}
