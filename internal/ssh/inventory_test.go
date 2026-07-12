// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: InventoryParse; TECH(8]: go test]
// @purpose Verify tolerant parsing of the inventory probe (os/kernel/cpu/mem/swap/ports/docker).
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, inventory, parse, os-release, ports, docker, meminfo
package ssh

import (
	"testing"
)

const sampleInventory = "=os=\nUbuntu 22.04.4 LTS\n=uname=\nLinux 5.15.0-112-generic x86_64\n" +
	"=cpu=\n Intel(R) Xeon(R) CPU E5-2680\n=meminfo=\nMemTotal:       4014080 kB\nSwapTotal:      1048576 kB\n" +
	"=up=\n 12:30:01 up 10 days,  3:42,  2 users\n=ports=\n22\n80\n443\n=docker=\nweb|nginx:alpine|Up 2 hours\ndb|postgres:15|Up 2 hours\n=pkgs=\n482\n=svc=\n23\n"

func TestParseInventory(t *testing.T) {
	inv := parseInventory(sampleInventory)
	if inv.OS != "Ubuntu 22.04.4 LTS" {
		t.Errorf("os: %q", inv.OS)
	}
	if inv.Arch != "x86_64" {
		t.Errorf("arch: %q", inv.Arch)
	}
	if inv.MemTotalMB != 3920 || inv.SwapTotalMB != 1024 {
		t.Errorf("mem/swap MB: %d/%d", inv.MemTotalMB, inv.SwapTotalMB)
	}
	if inv.CPUModel != "Intel(R) Xeon(R) CPU E5-2680" {
		t.Errorf("cpu: %q", inv.CPUModel)
	}
	if len(inv.Ports) != 3 || inv.Ports[0] != 22 || inv.Ports[2] != 443 {
		t.Errorf("ports: %v", inv.Ports)
	}
	if len(inv.Docker) != 2 {
		t.Errorf("docker: %v", inv.Docker)
	}
	if inv.Uptime != "10 days,  3:42" {
		t.Errorf("uptime: %q", inv.Uptime)
	}
	if inv.Packages != 482 || inv.Services != 23 {
		t.Errorf("packages/services: %d/%d", inv.Packages, inv.Services)
	}
}

func TestParseInventory_Empty(t *testing.T) {
	inv := parseInventory("")
	if inv.OS != "" || inv.MemTotalMB != 0 || len(inv.Ports) != 0 {
		t.Errorf("expected zero inventory, got %+v", inv)
	}
}
