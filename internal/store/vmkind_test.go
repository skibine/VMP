// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(7]: VMKind,DomainIPGuard; TECH(8]: go test]
// @purpose Verify the server/equipment split and the IP-as-domain guard: kind roundtrip through
//
//	create/update, default server for legacy rows and empty kind, invalid kind rejected, and
//	Domain.Validate refusing bare IPv4/IPv6 with the actionable message while real domains pass.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, vm kind, equipment, network, iot, web, domain validate, ip guard, default
// STRUCTURE: ▶ ┌store┐ → ○ CreateVM(kind)/UpdateVM → 〈roundtrip? default?〉 ; Domain.Validate(IP) → ◇ reject → ⎋
package store

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
)

func TestVMKind_RoundtripAndDefault(t *testing.T) {
	log, buf := testLogger(t)
	s, err := Open(filepath.Join(t.TempDir(), "kind.sqlite"), log)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	// Explicit equipment kind survives create/read.
	id, err := s.CreateVM(ctx, VM{Name: "Keenetic", Hostname: "203.0.113.99", PortSSH: 22, Kind: "equipment"})
	if err != nil {
		t.Fatalf("CreateVM equipment: %v", err)
	}
	v, _ := s.GetVM(ctx, id)
	if v.Kind != "equipment" {
		t.Fatalf("kind want equipment, got %q", v.Kind)
	}
	// Update flips back to server.
	v.Kind = "server"
	if err := s.UpdateVM(ctx, v); err != nil {
		t.Fatalf("UpdateVM: %v", err)
	}
	v, _ = s.GetVM(ctx, id)
	if v.Kind != "server" {
		t.Fatalf("kind after update want server, got %q", v.Kind)
	}
	// Empty kind normalizes to server.
	id2, _ := s.CreateVM(ctx, VM{Name: "srv", Hostname: "10.0.0.1", PortSSH: 22})
	v2, _ := s.GetVM(ctx, id2)
	if v2.Kind != "server" {
		t.Fatalf("empty kind want server default, got %q", v2.Kind)
	}
	// Invalid kind rejected at Validate.
	if _, err := s.CreateVM(ctx, VM{Name: "x", Hostname: "10.0.0.2", PortSSH: 22, Kind: "toaster"}); err == nil {
		t.Fatal("invalid kind must be rejected")
	}
	// Legacy granular kind (network) is no longer valid — the 0030 migration collapses it.
	if _, err := s.CreateVM(ctx, VM{Name: "y", Hostname: "10.0.0.3", PortSSH: 22, Kind: "network"}); err == nil {
		t.Fatal("legacy kind must be rejected post-collapse")
	}
	t.Logf("[IMP:8][TestVMKind][RESULT] equipment roundtrip, default=server, invalid+legacy=refused")
	printIMPFromBuf(t, buf)
}

func TestDomainValidate_IPGuard(t *testing.T) {
	cases := []struct {
		name string
		want bool // want rejection
	}{
		{"203.0.113.99", true},
		{"2a02:6b8::1", true},
		{"example.top", false},
		{"clinic.example.org", false}, // RFC 2606 doc domain (was a real third-party site)
	}
	for _, c := range cases {
		err := Domain{Name: c.name}.Validate()
		rejected := err != nil && strings.Contains(err.Error(), "IP")
		if rejected != c.want {
			t.Fatalf("%s: rejected=%v, want %v (err=%v)", c.name, rejected, c.want, err)
		}
	}
	// Store path rejects too (CreateDomain -> Validate).
	log, _ := testLogger(t)
	s, _ := Open(filepath.Join(t.TempDir(), "dg.sqlite"), log)
	t.Cleanup(func() { _ = s.Close() })
	if _, err := s.CreateDomain(context.Background(), Domain{Name: "203.0.113.99"}); err == nil {
		t.Fatal("CreateDomain must refuse a bare IP")
	}
	t.Logf("[IMP:8][TestDomainIP][RESULT] ipv4/ipv6 refused, domains pass, store path guarded")
}
