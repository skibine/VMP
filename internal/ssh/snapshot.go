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

	"github.com/skibine/vm-pulse/internal/logging"
)

// snapshotCMD is the single, fixed command run on the VM. Section markers make parsing robust.
// It collects memory (free), root disk (df), uptime, load average and CPU count. Nothing here is
// derived from user input — this string is the entire attack surface for the snapshot feature.
const snapshotCMD = `echo =mem=; free -m; echo =df=; df -hP /; echo =up=; uptime; echo =load=; cat /proc/loadavg; echo =cpu=; nproc`

// Snapshot is the parsed, display-ready result of a one-shot SSH metrics probe.
type Snapshot struct {
	MemTotalMB  int     `json:"mem_total_mb"`
	MemUsedMB   int     `json:"mem_used_mb"`
	DiskTotalGB float64 `json:"disk_total_gb"`
	DiskUsedGB  float64 `json:"disk_used_gb"`
	Load1       float64 `json:"load1"`
	Load5       float64 `json:"load5"`
	Load15      float64 `json:"load15"`
	CPUCount    int     `json:"cpu_count"`
	Uptime      string  `json:"uptime"` // human-readable, best-effort
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
	reDF   = regexp.MustCompile(`(?m)^\S+\s+([\d.]+)([KMGT])\s+([\d.]+)([KMGT])\s+[\d.]+[KMGT]?\s+[\d.]+%\s+/`)
	reLoad = regexp.MustCompile(`(\d+\.?\d*)\s+(\d+\.?\d*)\s+(\d+\.?\d*)`)
	reUp   = regexp.MustCompile(`up\s+(.+?),\s+\d+\s+users?`)
)

// parseSnapshot splits the combined output by section markers and extracts metrics tolerantly.
func parseSnapshot(out string) Snapshot {
	var s Snapshot
	section := func(tag string) string {
		marker := "=" + tag + "="
		i := strings.Index(out, marker)
		if i < 0 {
			return ""
		}
		rest := out[i+len(marker):]
		if j := strings.Index(rest, "\n="); j >= 0 {
			return rest[:j]
		}
		return rest
	}

	if m := reMem.FindStringSubmatch(section("mem")); len(m) == 3 {
		s.MemTotalMB, _ = strconv.Atoi(m[1])
		s.MemUsedMB, _ = strconv.Atoi(m[2])
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
	return s
}

// toGB converts a "df -h" magnitude+unit (e.g. "40","G") into gigabytes.
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
