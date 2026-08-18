// Package install — small read-only helpers shared by the audit collectors.
//
// region MODULE_CONTRACT [DOMAIN(5): Util; CONCEPT(6): Readers; TECH(6): os,net,exec]
// @purpose Keep the collectors terse: file field readers, a bounded exec runner, and the own-IP /
// @purpose public-IP predicates. All read-only; exec is whitelist-driven at the call sites.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: helpers, readTrim, readField, runCmd, ownIPs, hasPublicOwnIP, parseFloat, itoa
package install

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// readTrim returns the trimmed contents of a file ("" on any error).
func readTrim(path string) string {
	out, err := runRead(path)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(out))
}

// readField returns the n-th whitespace field of a file ("" on any error).
func readField(path string, idx int) string {
	out, err := runRead(path)
	if err != nil {
		return ""
	}
	fields := strings.Fields(string(out))
	if idx < 0 || idx >= len(fields) {
		return ""
	}
	return fields[idx]
}

// runRead is split so tests can stub it via the package-internal variable.
var runRead = func(path string) ([]byte, error) {
	return os.ReadFile(path)
}

// runCmd runs a command with a hard timeout and returns its stdout + error. The error distinguishes
// "binary not installed" (exec.ErrNotFound) from a permission/runtime failure — the caller maps those
// to "absent" vs "unknown" so the audit never FALSELY reports "no firewall" when it merely couldn't
// read it (e.g. ufw/iptables/nft all need root).
func runCmd(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	cctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(cctx, name, args...)
	var buf bytes.Buffer
	cmd.Stdout = &buf
	err := cmd.Run()
	return buf.String(), err
}

// isNotFound reports whether the command's binary is missing (truly "not installed").
func isNotFound(err error) bool {
	if err == nil {
		return false
	}
	return strings.Contains(err.Error(), "executable file not found") || strings.Contains(err.Error(), "no such file or directory")
}

// ownIPs returns non-loopback, non-link-local unicast addresses on the host's interfaces.
func ownIPs() []string {
	var out []string
	ifaces, err := net.Interfaces()
	if err != nil {
		return out
	}
	for _, ifc := range ifaces {
		addrs, err := ifc.Addrs()
		if err != nil {
			continue
		}
		for _, a := range addrs {
			ipNet, ok := a.(*net.IPNet)
			if !ok {
				continue
			}
			ip := ipNet.IP
			if ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() {
				continue
			}
			out = append(out, ip.String())
		}
	}
	return out
}

// hasPublicOwnIP reports whether any own interface carries a globally-routable IPv4 (i.e. the host
// is likely directly internet-facing, not behind NAT).
func hasPublicOwnIP(ips []string) bool {
	for _, s := range ips {
		ip := net.ParseIP(s)
		if ip == nil || ip.To4() == nil {
			continue
		}
		if !ip.IsGlobalUnicast() {
			continue
		}
		return true
	}
	return false
}

// looksLikeDatacenter applies a curated hosting-provider heuristic over ASN org/ISP/domain/PTR
// strings. ipwho.is does not expose a clean usage_type, so this matches known provider names —
// reliable enough for the "VPS in the internet vs home box" posture signal.
func looksLikeDatacenter(org, isp, domain, ptr string) bool {
	hay := strings.ToLower(org + " " + isp + " " + domain + " " + ptr)
	providers := []string{
		"hetzner", "digitalocean", "ovh", "vultr", "linode", "amazon", "aws", "ec2",
		"google", "gcp", "azure", "microsoft", "contabo", "scaleway", "upcloud", "leaseweb",
		"hivelocity", "kamatera", "hostinger", "choopa", "vps", "datacamp", "datacenter",
		"hosting", "cloud", "server", "colocation", "ovhcloud", "oracle cloud", "alibaba",
		"tencent", "selectel", "timeweb", "firstvds", "ru-vds", "aeza",
	}
	for _, p := range providers {
		if strings.Contains(hay, p) {
			return true
		}
	}
	return false
}

func parseFloat(s string) (float64, error) { return strconv.ParseFloat(s, 64) }
func itoa(n int) string                    { return strconv.Itoa(n) }
func boolStr(b bool) string {
	if b {
		return "true"
	}
	return "false"
}
