// Package monitor — external port scan: which TCP ports face the internet (no credentials, Plane A).
//
// region MODULE_CONTRACT [DOMAIN(8): Monitoring; CONCEPT(7]: PortScan; TECH(7]: net,parallel]
// @purpose Tell the operator which ports are open to the internet on a VM — without SSH/root.
//
//	A small, fixed set of common service ports is dialed in parallel from the VM Pulse host.
//
// @io (ctx, host) -> []PortStatus
// @invariants
//   - Credential-free: a plain TCP dial per port; closed ports return quickly (RST) or time out.
//   - Bounded: a fixed common-port list + per-port timeout + overall ctx deadline.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: port scan, open ports, exposed, nmap, tcp dial, common ports, plane a
// STRUCTURE: ▶ ┌host┐ → ∥ ∋port: 〈DialContext? open⟩ → ⊕ []PortStatus → ⎋ sorted
package monitor

import (
	"context"
	"fmt"
	"net"
	"sort"
	"sync"
	"time"
)

// PortStatus is one port's scan result.
type PortStatus struct {
	Port    int    `json:"port"`
	Service string `json:"service"`
	Open    bool   `json:"open"`
	LatMS   int    `json:"lat_ms"`
}

// commonPorts maps well-known ports to a human label (the scan set).
var commonPorts = []struct {
	Port    int
	Service string
}{
	{21, "ftp"}, {22, "ssh"}, {23, "telnet"}, {25, "smtp"}, {53, "dns"},
	{80, "http"}, {110, "pop3"}, {143, "imap"}, {443, "https"}, {465, "smtps"},
	{587, "submission"}, {993, "imaps"}, {995, "pop3s"}, {3306, "mysql"},
	{3389, "rdp"}, {5432, "postgres"}, {5900, "vnc"}, {6379, "redis"},
	{8080, "http-alt"}, {8443, "https-alt"}, {9000, "php-fpm/port"}, {9090, "prometheus"},
	{27017, "mongodb"}, {11211, "memcached"}, {6443, "k8s-api"},
}

// region FUNC_PortScan [DOMAIN(8): Monitoring; CONCEPT(7]: PortScan; TECH(7]: net]
// @purpose Dial each common port in parallel and report which are open (exposed to the internet).
// @complexity 5
// endregion FUNC_PortScan
func PortScan(ctx context.Context, host string, timeout time.Duration) []PortStatus {
	if host == "" {
		return []PortStatus{}
	}
	bctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()

	out := make([]PortStatus, len(commonPorts))
	var wg sync.WaitGroup
	for i, cp := range commonPorts {
		wg.Add(1)
		go func(i int, cp struct {
			Port    int
			Service string
		}) {
			defer wg.Done()
			start := time.Now()
			d := net.Dialer{}
			addr := net.JoinHostPort(host, fmt.Sprintf("%d", cp.Port))
			conn, err := d.DialContext(bctx, "tcp", addr)
			lat := int(time.Since(start).Milliseconds())
			if err == nil {
				_ = conn.Close()
				out[i] = PortStatus{Port: cp.Port, Service: cp.Service, Open: true, LatMS: lat}
				return
			}
			out[i] = PortStatus{Port: cp.Port, Service: cp.Service, Open: false}
		}(i, cp)
	}
	wg.Wait()
	// Surface open ports first, then by port number.
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Open != out[j].Open {
			return out[i].Open
		}
		return out[i].Port < out[j].Port
	})
	return out
}
