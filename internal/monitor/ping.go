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
	"bytes"
	"context"
	"fmt"
	"os"
	"os/exec"
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

// rePingRTT matches the RTT number + its time unit across locales AND console encodings:
//   - "ms"            English ("time=135ms")
//   - "мсек"/"мс"     Russian in UTF-8 (modern consoles)
//   - 0xAC 0xE1 ...   Russian "мс"/"мсек" in the cp866 OEM codepage (default RU Windows console) —
//                     those bytes are NOT valid UTF-8, so without them latency parses as 0 on RU Windows.
//   - 0xEC 0xF1       Russian "мс" in cp1251.
// TTL/bytes numbers lack a unit, so they never match. Parsed byte-level (not via regexp) because Go's
// regexp works on UTF-8 runes and cannot match the raw cp866 bytes of Russian "мс" (invalid UTF-8).
//
// parsePingRTT scans ping output for "<number><unit>", where unit is one of: ASCII "ms", UTF-8
// "мсек"/"мс" (modern consoles), cp866 "мс"/"мсек" (default RU Windows OEM codepage), cp1251 "мс".
func parsePingRTT(out []byte) float64 {
	for i := 0; i < len(out); i++ {
		if out[i] < '0' || out[i] > '9' {
			continue
		}
		j := i
		for j < len(out) && out[j] >= '0' && out[j] <= '9' {
			j++
		}
		if j < len(out) && out[j] == '.' { // fractional ms (e.g. 12.4ms)
			j++
			for j < len(out) && out[j] >= '0' && out[j] <= '9' {
				j++
			}
		}
		k := j
		for k < len(out) && (out[k] == ' ' || out[k] == '\t') { // optional space before unit
			k++
		}
		if hasTimeUnit(out[k:]) {
			f, _ := strconv.ParseFloat(string(out[i:j]), 64)
			return f
		}
		i = j
	}
	return 0
}

func hasTimeUnit(b []byte) bool {
	return bytes.HasPrefix(b, []byte("ms")) ||
		bytes.HasPrefix(b, []byte("мсек")) || bytes.HasPrefix(b, []byte("мс")) || // UTF-8
		bytes.HasPrefix(b, []byte{0xac, 0xe1, 0xa5, 0xaa}) || bytes.HasPrefix(b, []byte{0xac, 0xe1}) || // cp866 мсек/мс
		bytes.HasPrefix(b, []byte{0xec, 0xf1}) // cp1251 мс
}

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
	// Send 3 packets, "up" if ANY replies (exit 0). ICMP is rate-limited/dropped first by many
	// firewalls/providers, so a single packet yields spurious "no reply" on intermittent loss;
	// three packets avoids that false failure. Per-packet wait is bounded so all three finish well
	// within the overall timeout (no mid-run kill).
	perWait := timeout / 4
	if perWait < 500*time.Millisecond {
		perWait = 500 * time.Millisecond
	}
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		// Direct call to ping.exe via its full path (SystemRoot\System32\ping.exe) — no shell wrapper,
		// so it never trips "binary not found" on environments where bare-name PATH lookup fails.
		cmd = exec.CommandContext(cctx, windowsPing(), "-n", "3", "-w", strconv.FormatInt(perWait.Milliseconds(), 10), target)
	} else {
		cmd = exec.CommandContext(cctx, "ping", "-c", "3", "-W", strconv.FormatInt(int64(perWait.Seconds()), 10), target)
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		// No ping binary on the host (rare — minimal container) = environment limitation, not down.
		if execErr, ok := err.(*exec.Error); ok && execErr.Err == exec.ErrNotFound {
			return Result{Status: StatusUnknown, Message: "ping binary not found on this host"}
		}
		// Plain observation: VMPulse sent 3 ICMP echoes to the target and got no reply. This is what
		// was seen — NOT an interpretation ("host down"). Many hosts block ICMP; the box may still be
		// up (verify via the liveness/ssh check).
		return Result{Status: StatusCritical,
			Message: fmt.Sprintf("ping: no reply from %s", target),
			Detail:  map[string]any{"target": target}}
	}
	latency := parsePingRTT(out)
	return Result{Status: StatusOK, LatencyMS: latency,
		Message: fmt.Sprintf("ping: reply %.0fms from %s", latency, target),
		Detail:  map[string]any{"target": target}}
}
