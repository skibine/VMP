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
	"math/rand"
	"net"
	"sort"
	"strconv"
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

// wellKnown labels common ports (incl. non-standard app ports) so deep-scan results read like
// "8080 http-alt" rather than bare numbers.
var wellKnown = func() map[int]string {
	m := map[int]string{}
	for _, cp := range commonPorts {
		m[cp.Port] = cp.Service
	}
	for _, e := range []struct {
		p int
		s string
	}{
		{1080, "socks"}, {1194, "openvpn"}, {1723, "pptp"}, {1812, "radius"}, {1900, "ssdp"},
		{2049, "nfs"}, {2086, "cpanel"}, {2087, "cpanel-tls"}, {2222, "ssh-alt"}, {2375, "docker"},
		{2376, "docker-tls"}, {3000, "node/grafana"}, {3128, "squid"}, {3306, "mysql"}, {3478, "stun"},
		{4500, "ipsec-nat"}, {5000, "flask/upnp"}, {5353, "mdns"}, {5601, "kibana"}, {5672, "amqp"},
		{5984, "couchdb"}, {6000, "x11"}, {6379, "redis"}, {7474, "neo4j"}, {7687, "bolt"}, {8000, "http-alt"},
		{8333, "bitcoin"}, {8500, "consul"}, {8888, "jupyter/http"}, {9001, "tor"}, {9200, "elasticsearch"},
		{9300, "elasticsearch"}, {9418, "git"}, {9999, "abyss"}, {11211, "memcached"}, {15672, "rabbitmq"},
		{25565, "minecraft"}, {27015, "steam"}, {50070, "hdfs"},
	} {
		m[e.p] = e.s
	}
	return m
}()

// serviceOf returns a label for a port, or "" when unknown (the UI shows the bare number).
func serviceOf(port int) string {
	if s, ok := wellKnown[port]; ok {
		return s
	}
	return ""
}

// deepScanPorts builds the port list for a scope, SHUFFLED so the scan looks like scattered
// connections to an IDS rather than a sequential 1,2,3,... sweep (less likely to trip rules).
func deepScanPorts(scope string) []int {
	switch scope {
	case "full":
		ports := make([]int, 65535)
		for p := 1; p <= 65535; p++ {
			ports[p-1] = p
		}
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
		return ports
	default: // "fast": all privileged (1-1024) + common app ports beyond 1024
		seen := make(map[int]bool, 1100)
		ports := make([]int, 0, 1100)
		for p := 1; p <= 1024; p++ {
			ports = append(ports, p)
			seen[p] = true
		}
		for cp := range wellKnown {
			if !seen[cp] {
				ports = append(ports, cp)
				seen[cp] = true
			}
		}
		rand.Shuffle(len(ports), func(i, j int) { ports[i], ports[j] = ports[j], ports[i] })
		return ports
	}
}

// region FUNC_DeepScan [DOMAIN(8): Monitoring; CONCEPT(7]: DeepScan; TECH(7]: net,worker-pool]
// @purpose Dial a WIDE port range (fast: ~1k ports; full: all 65535) to find non-standard open
//
//	ports the fixed common-port scan misses. Pure TCP-connect (no raw sockets, no privileges),
//	cross-platform. A bounded worker pool + short per-port timeout keep it fast; closed ports RST
//	quickly, only filtered ports burn the full timeout. Returns ONLY open ports.
//
// @io (ctx, host, scope, perPortTimeout) -> []PortStatus (open only)
// @complexity 6
// endregion FUNC_DeepScan
func DeepScan(ctx context.Context, host, scope string, perPort time.Duration) []PortStatus {
	if host == "" {
		return nil
	}
	ports := deepScanPorts(scope)
	const concurrency = 512
	sem := make(chan struct{}, concurrency)
	var mu sync.Mutex
	var open []PortStatus
	var wg sync.WaitGroup
	for _, p := range ports {
		if err := ctx.Err(); err != nil {
			break // cancelled (UI abort / overall deadline)
		}
		wg.Add(1)
		go func(port int) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()
			pctx, cancel := context.WithTimeout(ctx, perPort)
			defer cancel()
			start := time.Now()
			conn, err := (&net.Dialer{}).DialContext(pctx, "tcp", net.JoinHostPort(host, strconv.Itoa(port)))
			if err != nil {
				return // closed / filtered / timed out — uninteresting
			}
			_ = conn.Close()
			lat := int(time.Since(start).Milliseconds())
			mu.Lock()
			open = append(open, PortStatus{Port: port, Service: serviceOf(port), Open: true, LatMS: lat})
			mu.Unlock()
		}(p)
	}
	wg.Wait()
	sort.SliceStable(open, func(i, j int) bool { return open[i].Port < open[j].Port })
	return open
}
