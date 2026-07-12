// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: VMCreds; TECH(8]: go test]
// @purpose Verify per-VM credential encryption at rest, transparent read, validation, delete.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, vm_credentials, SSH, encryption, validation, delete
package store

import (
	"context"
	"strings"
	"testing"
)

func TestVMCredentials_RoundTrip(t *testing.T) {
	s, _ := openTestStore(t)
	armVault(t, s)
	ctx := context.Background()

	vmID, _ := s.CreateVM(ctx, VM{Name: "v", Hostname: "h", PortSSH: 22})
	if err := s.SetVMCredentials(ctx, VMCredentials{VMID: vmID, SSHUser: "root", AuthType: "password", Secret: "hunter2"}); err != nil {
		t.Fatalf("SetVMCredentials: %v", err)
	}

	var raw string
	_ = s.DB.QueryRow(`SELECT secret FROM vm_credentials WHERE vm_id=?`, vmID).Scan(&raw)
	if strings.Contains(raw, "hunter2") || !strings.HasPrefix(raw, "enc:v1:") {
		t.Fatalf("vm secret must be encrypted at rest, got %q", raw)
	}

	c, has, err := s.GetVMCredentials(ctx, vmID)
	if err != nil || !has || c.Secret != "hunter2" || c.SSHUser != "root" {
		t.Fatalf("GetVMCredentials mismatch: has=%v c=%+v err=%v", has, c, err)
	}

	// Validation: password auth requires user+secret.
	if err := s.SetVMCredentials(ctx, VMCredentials{VMID: vmID, AuthType: "password"}); err == nil {
		t.Fatal("expected validation error for missing ssh_user/secret")
	}

	if err := s.DeleteVMCredentials(ctx, vmID); err != nil {
		t.Fatalf("DeleteVMCredentials: %v", err)
	}
	if _, has, _ := s.GetVMCredentials(ctx, vmID); has {
		t.Fatal("credentials should be gone after delete")
	}
}
