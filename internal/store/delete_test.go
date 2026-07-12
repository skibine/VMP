// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: DeleteVMCascade; TECH(8]: go test]
// @purpose Verify DeleteVM removes the VM AND its checks, check_results, metric_samples (no FK),
// credentials and host keys (FK cascade).
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, delete vm, cascade, checks, results, metrics, cleanup
package store

import (
	"context"
	"testing"
)

func TestDeleteVM_CleansAllChildren(t *testing.T) {
	s, _ := openTestStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, VM{Name: "del", Hostname: "h", PortSSH: 22})

	// seed children
	chkID, _ := s.CreateCheck(ctx, Check{VMID: &vmID, TargetType: "vm", CheckType: "tcp", IntervalSec: 60})
	_ = s.SetVMCredentials(ctx, VMCredentials{VMID: vmID, SSHUser: "u", AuthType: "password", Secret: "p"})
	_ = s.SetHostKey(ctx, HostKey{VMID: vmID, Fingerprint: "sha256:X"})
	_, _ = s.DB.ExecContext(ctx, `INSERT INTO check_results (check_id, status) VALUES (?, 'ok')`, chkID)
	_ = s.RecordSamples(ctx, vmID, map[string]float64{"mem_used_mb": 1})

	if err := s.DeleteVM(ctx, vmID); err != nil {
		t.Fatalf("DeleteVM: %v", err)
	}

	count := func(q string, args ...any) int {
		var n int
		_ = s.DB.QueryRowContext(ctx, q, args...).Scan(&n)
		return n
	}
	if count(`SELECT COUNT(*) FROM checks WHERE vm_id=?`, vmID) != 0 {
		t.Error("checks not cleaned")
	}
	if count(`SELECT COUNT(*) FROM check_results WHERE check_id=?`, chkID) != 0 {
		t.Error("check_results not cleaned")
	}
	if count(`SELECT COUNT(*) FROM metric_samples WHERE vm_id=?`, vmID) != 0 {
		t.Error("metric_samples not cleaned")
	}
	if count(`SELECT COUNT(*) FROM vm_credentials WHERE vm_id=?`, vmID) != 0 {
		t.Error("vm_credentials not cascade-deleted")
	}
	if count(`SELECT COUNT(*) FROM vm_hostkeys WHERE vm_id=?`, vmID) != 0 {
		t.Error("vm_hostkeys not cascade-deleted")
	}
	if _, err := s.GetVM(ctx, vmID); err != ErrNotFound {
		t.Errorf("vm still present after delete: %v", err)
	}
}
