// Package monitor — ICMP ping checker.
//
// region MODULE_CONTRACT [DOMAIN(7): Monitoring; CONCEPT(7): ICMP; TECH(8): x/net/icmp]
// @purpose Measure ICMP echo round-trip latency. Uses unprivileged ICMP (SOCK_DGRAM) which
//
//	requires the process to be in the host's ping_group_range (or CAP_NET_RAW).
//
// @invariants
//   - If the host does not permit unprivileged ICMP, the result is StatusUnknown with the
//     reason (NOT critical) — this is an environment limitation, not a target failure.
//   - Empty target -> unknown.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: ping, icmp, echo, rtt, latency, unprivileged, CAP_NET_RAW
// STRUCTURE: ▶ ┌target┐ → ○ icmp.ListenPacket(udp4) → ⚡ Echo WriteTo → ⊕ ReadFrom → ⎋ RTT
package monitor

import (
	"context"
	"net"
	"strings"
	"sync/atomic"
	"time"

	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
)

// pingID seeds a per-process echo ID (incremented per probe).
var pingID uint32

// region STRUCT_PingChecker [DOMAIN(7): Monitoring; CONCEPT(6): Plugin; TECH(8): x/net/icmp]
// @purpose ICMP echo (ping) checker.
// endregion STRUCT_PingChecker
type PingChecker struct{}

func (PingChecker) Type() string { return "ping" }

// region FUNC_PingChecker_Run [DOMAIN(7): Monitoring; CONCEPT(7): Probe; TECH(8): x/net/icmp]
// @purpose Send one ICMP echo and measure the RTT.
// @complexity 6
// endregion FUNC_PingChecker_Run
func (PingChecker) Run(ctx context.Context, target string, params map[string]any) Result {
	if strings.TrimSpace(target) == "" {
		return Result{Status: StatusUnknown, Message: "empty target"}
	}
	timeout := timeoutOf(params, 5*time.Second)

	c, err := icmp.ListenPacket("udp4", "0.0.0.0")
	if err != nil {
		// Environment cannot do unprivileged ICMP — surface as unknown, not a target failure.
		return Result{Status: StatusUnknown,
			Message: "icmp unavailable (need ping_group_range or CAP_NET_RAW): " + err.Error()}
	}
	defer c.Close()

	dst, err := net.ResolveIPAddr("ip4", target)
	if err != nil {
		return Result{Status: StatusCritical, Message: "resolve: " + err.Error()}
	}
	_ = c.SetDeadline(time.Now().Add(timeout))

	id := int(atomic.AddUint32(&pingID, 1) & 0xffff)
	msg := icmp.Message{
		Type: ipv4.ICMPTypeEcho, Code: 0,
		Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("VMPULSE-PING")},
	}
	wb, err := msg.Marshal(nil)
	if err != nil {
		return Result{Status: StatusUnknown, Message: "marshal: " + err.Error()}
	}
	start := time.Now()
	if _, err := c.WriteTo(wb, dst); err != nil {
		return Result{Status: StatusCritical, Message: "write: " + err.Error()}
	}
	rb := make([]byte, 1500)
	n, peer, err := c.ReadFrom(rb)
	latency := float64(time.Since(start).Microseconds()) / 1000.0
	if err != nil {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: "read: " + err.Error(),
			Detail: map[string]any{"target": target}}
	}
	rm, err := icmp.ParseMessage(1, rb[:n]) // 1 = ICMPv4 protocol number
	if err != nil {
		return Result{Status: StatusUnknown, Message: "parse: " + err.Error()}
	}
	if rm.Type != ipv4.ICMPTypeEchoReply {
		return Result{Status: StatusCritical, LatencyMS: latency, Message: "non-echo-reply",
			Detail: map[string]any{"target": target, "type": rm.Type}}
	}
	peerStr := ""
	if peer != nil {
		peerStr = peer.String()
	}
	return Result{Status: StatusOK, LatencyMS: latency, Message: "echo reply",
		Detail: map[string]any{"target": target, "peer": peerStr}}
}
