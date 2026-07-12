// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): HostKeyTOFU; TECH(8): go test]
// @purpose Verify TOFU host-key Get/Set/Delete and cascade with VM deletion.
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, host key, TOFU, fingerprint, vm_hostkeys, cascade
package store

import (
	"context"
	"testing"
)

func TestHostKeys_TOFU(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	vmID, err := s.CreateVM(ctx, VM{Name: "tofu", Hostname: "h", PortSSH: 22})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}

	// first read: none stored
	if hk, ok, err := s.GetHostKey(ctx, vmID); err != nil || ok {
		t.Fatalf("expected no stored host key, got %+v ok=%v err=%v", hk, ok, err)
	}

	// set (first connect records fingerprint)
	if err := s.SetHostKey(ctx, HostKey{VMID: vmID, Fingerprint: "sha256:AAAA", Algo: "ssh-ed25519"}); err != nil {
		t.Fatalf("SetHostKey: %v", err)
	}
	hk, ok, err := s.GetHostKey(ctx, vmID)
	if err != nil || !ok || hk.Fingerprint != "sha256:AAAA" {
		t.Fatalf("GetHostKey after set: %+v ok=%v err=%v", hk, ok, err)
	}

	// upsert replaces
	if err := s.SetHostKey(ctx, HostKey{VMID: vmID, Fingerprint: "sha256:BBBB", Algo: "ssh-ed25519"}); err != nil {
		t.Fatalf("SetHostKey upsert: %v", err)
	}
	hk, _, _ = s.GetHostKey(ctx, vmID)
	if hk.Fingerprint != "sha256:BBBB" {
		t.Fatalf("upsert did not replace: %+v", hk)
	}

	// delete (TOFU reset)
	if err := s.DeleteHostKey(ctx, vmID); err != nil {
		t.Fatalf("DeleteHostKey: %v", err)
	}
	if _, ok, _ := s.GetHostKey(ctx, vmID); ok {
		t.Fatalf("host key still present after delete")
	}
}

func TestHostKeys_CascadeWithVM(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()

	vmID, _ := s.CreateVM(ctx, VM{Name: "tofu-cascade", Hostname: "h", PortSSH: 22})
	_ = s.SetHostKey(ctx, HostKey{VMID: vmID, Fingerprint: "sha256:CCCC", Algo: "ssh-rsa"})

	// FK pragma should cascade on VM delete (store.Open enables PRAGMA foreign_keys=ON).
	if _, err := s.DB.ExecContext(ctx, `DELETE FROM vms WHERE id=?`, vmID); err != nil {
		t.Fatalf("delete vm: %v", err)
	}
	if _, ok, _ := s.GetHostKey(ctx, vmID); ok {
		t.Fatalf("host key was not cascade-deleted with VM")
	}
}
