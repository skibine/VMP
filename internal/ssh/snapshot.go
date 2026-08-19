// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(8): Snapshot; TECH(8): x/crypto/ssh,regex]
// @purpose Provide instant CPU/RAM/disk/load/uptime for a VM by running a FIXED, safe command set
//
//	over an open SSH connection — no agent install required (design §5 level 3 "SSH-snapshot").
//
// @io (ctx, *gossh.Client) -> (Snapshot, error)
// @invariants
//   - The command is a compile-time constant: user input NEVER reaches the shell (no RCE surface).
//   - Parsing is tolerant: missing tools (e.g. no `free`) leave the field at zero, not an error.
//   - Result is ephemeral (not persisted); continuous metrics belong to the agent slice.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: snapshot, metrics, free, df, uptime, loadavg, nproc, cpu, ram, disk, ssh
// STRUCTURE: ▶ ┌client┐ → ⚡ CombinedOutput(FIXED_CMD) → ◇ section split → ⊕ regex parse → ⎷ Snapshot
package ssh

import (
	"context"
	"fmt"
	"regexp"
	"strconv"
	"strings"

	gossh "golang.org/x/crypto/ssh"

	"github.com/skibine/vmp/internal/logging"
)

// snapshotCMD is the single, fixed command run on the VM. Section markers make parsing robust.
// Collects memory/swap (free), root disk (df), uptime, load+proc-count (loadavg), cpu cores (nproc),
// CPU% via a 1s /proc/stat delta (cstat1/cstat2), and established TCP connections (/proc/net/tcp).
// Nothing here is derived from user input — this string is the entire attack surface.
const snapshotCMD = `echo =mem=; free -m; echo =df=; df -hP /; echo =up=; uptime; echo =load=; cat /proc/loadavg; echo =cpu=; nproc; echo =cstat1=; head -n1 /proc/stat; sleep 1; echo =cstat2=; head -n1 /proc/stat; echo =tcp=; awk 'NR>1 && $4=="01"{c++} END{print c+0}' /proc/net/tcp; echo =net=; cat /proc/net/dev`

// Snapshot is the parsed, display-ready result of a one-shot SSH metrics probe.
type Snapshot struct {
	MemTotalMB  int     `json:"mem_total_mb"`
	MemUsedMB   int     `json:"mem_used_mb"`
	SwapTotalMB int     `json:"swap_total_mb"`
	SwapUsedMB  int     `json:"swap_used_mb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskUsedGB  float64 `json:"disk_used_gb"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	CPUCount    int     `json:"cpu_count"`
	CPUPct      float64 `json:"cpu_pct"`   // 0..100, 1s average via /proc/stat delta
	TCPConns    int     `json:"tcp_conns"` // established TCP connections
	ProcCount   int     `json:"proc_count"`
	NetIface    string  `json:"net_iface"`
	NetRxBytes  int64   `json:"net_rx_bytes"` // cumulative bytes received on the main interface
	NetTxBytes  int64   `json:"net_tx_bytes"` // cumulative bytes transmitted on the main interface
	Uptime      string  `json:"uptime"`       // human-readable, best-effort
}

// region FUNC_Dialer_Snapshot [DOMAIN(8): Observability; CONCEPT(8): Snapshot; TECH(8): ssh,regex]
// @purpose Run the fixed snapshot command over an open SSH client and return parsed metrics so the
//
//	UI can show live CPU/RAM/disk without an installed agent.
//
// @io (ctx, *gossh.Client) -> (Snapshot, error)
// @complexity 6
// endregion FUNC_Dialer_Snapshot
func (d *Dialer) Snapshot(ctx context.Context, client *gossh.Client) (Snapshot, error) {
	sess, err := client.NewSession()
	if err != nil {
		return Snapshot{}, fmt.Errorf("snapshot: new session: %w", err)
	}
	defer sess.Close()

	out, err := sess.CombinedOutput(snapshotCMD)
	if err != nil {
		logging.LDD(d.logger, 9, "Snapshot", "RUN_FAIL", err.Error())
		return Snapshot{}, fmt.Errorf("snapshot: run: %w", err)
	}
	s := parseSnapshot(string(out))
	logging.LDD(d.logger, 8, "Snapshot", "OK",
		fmt.Sprintf("mem=%d/%dMB disk=%.1f/%.1fGB load=%.2f cpus=%d", s.MemUsedMB, s.MemTotalMB, s.DiskUsedGB, s.DiskTotalGB, s.Load1, s.CPUCount))
	return s, nil
}

// --- parsers (tolerant; missing section => zero value, not error) ---

var (
	reMem  = regexp.MustCompile(`(?m)^Mem:\s+(\d+)\s+(\d+)`)
	reSwap = regexp.MustCompile(`(?m)^Swap:\s+(\d+)\s+(\d+)`)
	reDF   = regexp.MustCompile(`(?m)^\S+\s+([\d.]+)([KMGT])\s+([\d.]+)([KMGT])\s+[\d.]+[KMGT]?\s+[\d.]+%\s+/`)
	reLoad = regexp.MustCompile(`(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)`)
	reUp   = regexp.MustCompile(`up\s+(.+?),\s+\d+\s+users?`)
)

// splitSections parses "=tag=\n...\n=tag2=" framed output into a tag->content map. Shared by the
// snapshot and inventory parsers; tolerant of missing/empty sections. Markers are lines matching
// "^=word=$"; empty sections map to "" (they never swallow the following marker).
func splitSections(out string) map[string]string {
	res := map[string]string{}
	var cur string
	var body strings.Builder
	flush := func() {
		if cur != "" {
			res[cur] = strings.TrimRight(body.String(), "\n")
		}
	}
	for _, ln := range strings.Split(out, "\n") {
		if isMarker(ln) {
			flush()
			cur = strings.Trim(ln, "=")
			body.Reset()
		} else {
			body.WriteString(ln + "\n")
		}
	}
	flush()
	return res
}

// isMarker reports whether a line is a section marker like "=cpu=" or "=cstat1=".
func isMarker(ln string) bool {
	if len(ln) < 3 || ln[0] != '=' || ln[len(ln)-1] != '=' {
		return false
	}
	inner := ln[1 : len(ln)-1]
	if inner == "" {
		return false
	}
	for _, r := range inner {
		if !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '_' {
			return false
		}
	}
	return true
}

// parseSnapshot splits the combined output by section markers and extracts metrics tolerantly.
func parseSnapshot(out string) Snapshot {
	var s Snapshot
	sec := splitSections(out)
	section := func(tag string) string { return sec[tag] }

	if m := reMem.FindStringSubmatch(section("mem")); len(m) == 3 {
		s.MemTotalMB, _ = strconv.Atoi(m[1])
		s.MemUsedMB, _ = strconv.Atoi(m[2])
	}
	if m := reSwap.FindStringSubmatch(section("mem")); len(m) == 3 {
		s.SwapTotalMB, _ = strconv.Atoi(m[1])
		s.SwapUsedMB, _ = strconv.Atoi(m[2])
	}
	if m := reDF.FindStringSubmatch(section("df")); len(m) == 5 {
		s.DiskTotalGB = toGB(m[1], m[2])
		s.DiskUsedGB = toGB(m[3], m[4])
	}
	if m := reLoad.FindStringSubmatch(section("load")); len(m) == 4 {
		s.Load1, _ = strconv.ParseFloat(m[1], 64)
		s.Load5, _ = strconv.ParseFloat(m[2], 64)
		s.Load15, _ = strconv.ParseFloat(m[3], 64)
	}
	if m := reUp.FindStringSubmatch(section("up")); len(m) == 2 {
		s.Uptime = strings.TrimSpace(m[1])
	}
	if c := strings.TrimSpace(section("cpu")); c != "" {
		if n, err := strconv.Atoi(c); err == nil {
			s.CPUCount = n
		}
	}
	s.CPUPct = cpuPctFromStat(section("cstat1"), section("cstat2"))
	if t := strings.TrimSpace(section("tcp")); t != "" {
		if n, err := strconv.Atoi(t); err == nil {
			s.TCPConns = n
		}
	}
	s.ProcCount = procCountFromLoadavg(section("load"))
	s.NetIface, s.NetRxBytes, s.NetTxBytes = netFromProcDev(section("net"))
	return s
}

// netFromProcDev parses /proc/net/dev and returns the busiest non-loopback interface and its
// cumulative rx/tx byte counters. Used by the poller to compute rx/tx rates across polls.
func netFromProcDev(s string) (iface string, rx, tx int64) {
	var best string
	var bestSum int64
	for _, line := range strings.Split(s, "\n") {
		i := strings.Index(line, ":")
		if i <= 0 {
			continue
		}
		name := strings.TrimSpace(line[:i])
		if name == "lo" {
			continue
		}
		fields := strings.Fields(line[i+1:])
		if len(fields) < 9 {
			continue
		}
		r, _ := strconv.ParseInt(fields[0], 10, 64) // rx_bytes
		t, _ := strconv.ParseInt(fields[8], 10, 64) // tx_bytes
		if r+t > bestSum {                          // busiest iface (rx+tx) wins
			bestSum = r + t
			best = name
			rx, tx = r, t
		}
		iface = best
	}
	return iface, rx, tx
}

// cpuPctFromStat computes a 0..100 CPU busy percentage from two /proc/stat "cpu" lines sampled ~1s
// apart. Returns 0 when either sample is missing or the delta is non-positive.
func cpuPctFromStat(line1, line2 string) float64 {
	t1, i1, ok1 := cpuStatTicks(line1)
	t2, i2, ok2 := cpuStatTicks(line2)
	if !ok1 || !ok2 || t2-t1 <= 0 {
		return 0
	}
	busyDelta := (t2 - i2) - (t1 - i1)
	totalDelta := t2 - t1
	pct := 100 * float64(busyDelta) / float64(totalDelta)
	if pct < 0 {
		pct = 0
	}
	if pct > 100 {
		pct = 100
	}
	return pct
}

// cpuStatTicks returns (totalTicks, idleTicks, ok) from a /proc/stat cpu aggregate line. total is the
// sum of all tick columns; idle is idle+iowait (standard "idle" accounting).
func cpuStatTicks(line string) (int64, int64, bool) {
	fields := strings.Fields(line)
	if len(fields) < 5 || fields[0] != "cpu" {
		return 0, 0, false
	}
	var total int64
	for _, f := range fields[1:] {
		n, err := strconv.ParseInt(f, 10, 64)
		if err != nil {
			return 0, 0, false
		}
		total += n
	}
	idle, _ := strconv.ParseInt(fields[4], 10, 64) // idle (index 4: cpu user nice system IDLE)
	idleIowait := idle
	if len(fields) >= 6 {
		iow, _ := strconv.ParseInt(fields[5], 10, 64)
		idleIowait += iow
	}
	return total, idleIowait, true
}

// procCountFromLoadavg parses the 4th field of /proc/loadavg ("running/total") -> total process count.
func procCountFromLoadavg(s string) int {
	// fields: "0.10 0.05 0.01 1/123 4567" -> 4th field "1/123"
	fields := strings.Fields(s)
	if len(fields) < 4 {
		return 0
	}
	parts := strings.SplitN(fields[3], "/", 2)
	if len(parts) != 2 {
		return 0
	}
	n, _ := strconv.Atoi(parts[1])
	return n
}

// region FUNC_Dialer_Collect [DOMAIN(8): Observability; CONCEPT(8): Collect; TECH(8): ssh]
// @purpose One-stop metric collection for a VM: dial, run the snapshot, and map it to the flat
//
//	metric_samples names used by the poller / push pipeline. Closes the SSH client.
//
// @io (ctx, vmID) -> (map[string]float64, error)
// @complexity 5
// endregion FUNC_Dialer_Collect
func (d *Dialer) Collect(ctx context.Context, vmID int64) (map[string]float64, error) {
	client, _, err := d.Dial(ctx, vmID)
	if err != nil {
		return nil, err
	}
	defer client.Close()
	s, err := d.Snapshot(ctx, client)
	if err != nil {
		return nil, err
	}
	return map[string]float64{
		"mem_used_mb":   float64(s.MemUsedMB),
		"mem_total_mb":  float64(s.MemTotalMB),
		"swap_used_mb":  float64(s.SwapUsedMB),
		"swap_total_mb": float64(s.SwapTotalMB),
		"disk_used_gb":  s.DiskUsedGB,
		"disk_total_gb": s.DiskTotalGB,
		"load1":         s.Load1,
		"load5":         s.Load5,
		"load15":        s.Load15,
		"cpu_count":     float64(s.CPUCount),
		"cpu_pct":       s.CPUPct,
		"tcp_conns":     float64(s.TCPConns),
		"proc_count":    float64(s.ProcCount),
		"net_rx_bytes":  float64(s.NetRxBytes),
		"net_tx_bytes":  float64(s.NetTxBytes),
	}, nil
}
func toGB(val, unit string) float64 {
	n, _ := strconv.ParseFloat(val, 64)
	switch strings.ToUpper(unit) {
	case "K":
		return n / 1024 / 1024
	case "M":
		return n / 1024
	case "G":
		return n
	case "T":
		return n * 1024
	}
	return n
}
