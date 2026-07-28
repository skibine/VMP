// Package monitor — ICMP ping checker (via the system ping binary).
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): ICMP; TECH(7): os/exec]
// @purpose Measure ICMP echo reachability + RTT by invoking the host's native `ping` command.
//
//	Why not raw sockets: Go's x/net/icmp unprivileged (SOCK_DGRAM) mode works on Linux but NOT on
//	Windows (Windows doesn't implement that socket type), and raw ICMP needs admin everywhere.
//	The system `ping` binary works for every unprivileged user on every OS — on Windows ping.exe
//	uses IcmpSendEcho via the system ICMP API, on Linux/macOS the ping binary carries CAP_NET_RAW.
//
// @invariants
//   - ping binary not found on host -> StatusUnknown (environment limitation, not a target failure).
//   - ping ran but no reply -> StatusCritical (host down / dropping ICMP).
//   - Exit 0 + a parsed latency -> StatusOK.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ping, icmp, echo, rtt, latency, exec, system ping, windows, cross-platform
// STRUCTURE: ▶ ┌target┐ → ○ exec ping (-n/-c 1) → 〈exit 0? up : down〉 → ⊕ parse time=Xms → ⎷ Result
package monitor

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"
)

// windowsPing returns the absolute path to ping.exe via %SystemRoot% (always set on Windows),
// bypassing PATH/PATHEXT resolution — Go's exec.Command("ping") sometimes fails to find ping.exe
// even though System32 is in PATH. Falls back to the bare "ping" name if SystemRoot is unset.
func windowsPing() string {
	if sr := os.Getenv("SystemRoot"); sr != "" {
		p := sr + `\System32\ping.exe`
		if _, err := os.Stat(p); err == nil {
			return p
		}
	}
	return "ping"
}

// region STRUCT_PingChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(7): os/exec]
// @purpose ICMP echo (ping) checker via the system ping binary.
// endregion STRUCT_PingChecker
type PingChecker struct{}

func (PingChecker) Type() string { return "ping" }

// rePingRTT matches "135ms" / "135.4 ms" / "135мс" / "135 мсек" anywhere in ping output, so it works
// across locales (English "time=135ms", Russian "время=135мс", etc.). TTL/bytes numbers lack the
// ms unit, so they never match.
var rePingRTT = regexp.MustCompile(`([0-9]+(?:\.[0-9]+)?)\s*(ms|мсек|мс)`)

// region FUNC_PingChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(7): os/exec]
// @purpose Run the system ping once against the target and derive status + latency from its output.
// @complexity 4
// endregion FUNC_PingChecker_Run
func (PingChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	if strings.TrimSpace(target) == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	timeout := timeoutOf(params, 5*time.Second)
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	// Windows: ping -n 1 -w <ms>. Unix: ping -c 1 -W <sec>.
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.CommandContext(cctx, windowsPing(), "-n", "1", "-w", strconv.FormatInt(timeout.Milliseconds(), 10), target)
	} else {
		cmd = exec.CommandContext(cctx, "ping", "-c", "1", "-W", strconv.FormatInt(int64(timeout.Seconds()), 10), target)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// No ping binary on the host (rare — minimal container) = environment limitation, not down.
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return Result{Status: StatusUnknown, Message: "ping binary not found on this host"}
		}
		// ping ran but exited non-zero: no reply (host down, unreachable, or dropping ICMP).
		return Result{Status: StatusCritical, Message: "no reply (host down or unreachable)",
			Detail: map[string]any{"target": target}}
	}
	latency := 0.0
	if m := rePingRTT.FindStringSubmatch(string(out)); len(m) == 3 {
		latency, _ = strconv.ParseFloat(m[1], 64)
	}
	return Result{Status: StatusOK, LatencyMS: latency,
		Message: fmt.Sprintf("echo reply %.0fms", latency),
		Detail: map[string]any{"target": target}}
}
