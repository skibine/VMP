// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(8): Inventory; TECH(8): ssh,regex]
// @purpose Collect a one-shot "VPS profile" (OS, kernel, CPU model, RAM/SWAP totals, uptime,
// listening TCP ports, docker containers) over SSH. Triggered on credential save so the user
// immediately sees what the box is. Static facts (not time-series) — distinct from Snapshot metrics.
// @io (ctx, *gossh.Client) -> (Inventory, error)
// @invariants
//   - The command is a compile-time constant: no user input reaches the shell (no RCE surface).
//   - Parsing is tolerant: a missing tool/section leaves the field empty, not an error.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: inventory, system, os-release, kernel, cpu model, meminfo, ports, docker, profile
// STRUCTURE: ▶ ┌client┐ → ⚡ CombinedOutput(FIXED) → ◇ splitSections → ⊕ regex parse → ⎷ Inventory
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

// inventoryCMD is the fixed one-shot facts probe. Section markers make parsing robust. Nothing here
// is derived from user input.
const inventoryCMD = `echo =os=; (. /etc/os-release 2>/dev/null && echo "$PRETTY_NAME") || uname -sr
echo =uname=; uname -srm
echo =cpu=; grep -m1 'model name' /proc/cpuinfo 2>/dev/null | cut -d: -f2
echo =meminfo=; grep -E 'MemTotal|SwapTotal' /proc/meminfo 2>/dev/null
echo =up=; uptime
echo =ports=; (ss -tlnH 2>/dev/null || netstat -tln 2>/dev/null) | grep -oE ':[0-9]+' | tr -d : | sort -un | head -60
echo =docker=; (docker ps --format '{{.Names}}|{{.Image}}|{{.Status}}' 2>/dev/null) | head -30
echo =pkgs=; (dpkg -l 2>/dev/null | grep -c '^ii') || echo 0
echo =pkgsn=; (dpkg -l 2>/dev/null | awk '/^ii/{print $2}' | head -400)
echo =svc=; (systemctl list-units --type=service --state=running --no-legend 2>/dev/null | wc -l) || echo 0
echo =svcs=; (systemctl list-units --type=service --state=running --no-legend 2>/dev/null | awk '{print $1}' | sed 's/\.service$//' | head -80)`

// Inventory is a parsed VPS profile (static facts).
type Inventory struct {
	OS           string   `json:"os"`
	Kernel       string   `json:"kernel"`
	Arch         string   `json:"arch"`
	CPUModel     string   `json:"cpu_model"`
	MemTotalMB   int      `json:"mem_total_mb"`
	SwapTotalMB  int      `json:"swap_total_mb"`
	Uptime       string   `json:"uptime"`
	Ports        []int    `json:"ports"`
	Docker       []string `json:"docker"`
	Packages     int      `json:"packages"`
	PackagesList []string `json:"packages_list"`
	Services     int      `json:"services"`
	ServicesList []string `json:"services_list"`
}

// region FUNC_Dialer_Inventory [DOMAIN(8): Observability; CONCEPT(8): Inventory; TECH(8): ssh,regex]
// @purpose Run the fixed facts probe over an open SSH client and return a parsed VPS profile.
// @io (ctx, *gossh.Client) -> (Inventory, error)
// @complexity 6
// endregion FUNC_Dialer_Inventory
func (d *Dialer) Inventory(ctx context.Context, client *gossh.Client) (Inventory, error) {
	sess, err := client.NewSession()
	if err != nil {
		return Inventory{}, fmt.Errorf("inventory: new session: %w", err)
	}
	defer sess.Close()
	out, err := sess.CombinedOutput(inventoryCMD)
	if err != nil {
		logging.LDD(d.logger, 9, "Inventory", "RUN_FAIL", err.Error())
		return Inventory{}, fmt.Errorf("inventory: run: %w", err)
	}
	inv := parseInventory(string(out))
	logging.LDD(d.logger, 8, "Inventory", "OK",
		fmt.Sprintf("os=%q ports=%d docker=%d", inv.OS, len(inv.Ports), len(inv.Docker)))
	return inv, nil
}

var (
	reMemLine = regexp.MustCompile(`(?m)^(MemTotal|SwapTotal):\s+(\d+)`)
	reUpInv   = regexp.MustCompile(`up\s+(.+?),\s+\d+\s+users?`)
)

// parseInventory extracts the VPS profile from the sectioned probe output (tolerant).
func parseInventory(out string) Inventory {
	sec := splitSections(out)
	var inv Inventory

	inv.OS = clean(sec["os"])
	parts := strings.Fields(sec["uname"])
	if len(parts) >= 1 {
		inv.Kernel = strings.Join(parts[:min(2, len(parts))], " ")
	}
	if len(parts) >= 3 {
		inv.Arch = parts[2]
	} else if len(parts) == 2 {
		inv.Arch = parts[1]
	}
	inv.CPUModel = clean(sec["cpu"])
	for _, m := range reMemLine.FindAllStringSubmatch(sec["meminfo"], -1) {
		kb, _ := strconv.Atoi(m[2])
		mb := kb / 1024
		if m[1] == "MemTotal" {
			inv.MemTotalMB = mb
		} else {
			inv.SwapTotalMB = mb
		}
	}
	if m := reUpInv.FindStringSubmatch(sec["up"]); len(m) == 2 {
		inv.Uptime = strings.TrimSpace(m[1])
	}
	for _, line := range strings.Split(sec["ports"], "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if p, err := strconv.Atoi(line); err == nil {
			inv.Ports = append(inv.Ports, p)
		}
	}
	for _, line := range strings.Split(sec["docker"], "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			inv.Docker = append(inv.Docker, line)
		}
	}
	inv.Packages = 0
	if v, err := strconv.Atoi(strings.TrimSpace(sec["pkgs"])); err == nil {
		inv.Packages = v
	}
	for _, line := range strings.Split(sec["pkgsn"], "\n") {
		if name := strings.TrimSpace(line); name != "" {
			inv.PackagesList = append(inv.PackagesList, name)
		}
	}
	if v, err := strconv.Atoi(strings.TrimSpace(sec["svc"])); err == nil {
		inv.Services = v
	}
	for _, line := range strings.Split(sec["svcs"], "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			inv.ServicesList = append(inv.ServicesList, line)
		}
	}
	return inv
}

func clean(s string) string { return strings.TrimSpace(strings.Trim(s, "\"'")) }
