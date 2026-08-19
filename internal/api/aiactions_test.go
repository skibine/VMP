// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): AIActionApproval; TECH(8): go test]
// @purpose Regression for the approve-path refactor: executeApprovedAction is now the single
//
//	execution door shared by the web button and the Telegram bridge (Server.ApproveAIAction).
//	Uses a VM with no credentials so the dial fails — the action must resolve to status=error
//	(NOT a Go error), and a second approve must be rejected as not-pending.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, approve, ai action, executeApprovedAction, ApproveAIAction, telegram
// STRUCTURE: ▶ ┌store+pending action┐ → ○ ApproveAIAction → 〈dial fail → status=error〉 → ○ again → ◇ notPending → ⎋
package api

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/skibine/vmp/internal/store"
)

func TestApproveAIAction_SharedPathNotPending(t *testing.T) {
	srv, buf := newServer(t)
	ctx := context.Background()
	st := srv.store

	vmID, err := st.CreateVM(ctx, store.VM{Name: "v", Hostname: "203.0.113.99", PortSSH: 22})
	if err != nil {
		t.Fatalf("CreateVM: %v", err)
	}
	actID, err := st.CreateAIAction(ctx, store.AIAction{VMID: vmID, Command: "uptime", Reason: "test"})
	if err != nil {
		t.Fatalf("CreateAIAction: %v", err)
	}

	// First approve: dial fails (no credentials stored) -> action resolves to error, nil Go error.
	status, out, aerr := srv.ApproveAIAction(ctx, actID, "telegram")
	if aerr != nil {
		t.Fatalf("first approve: want nil Go error (action resolved), got %v", aerr)
	}
	if status != "error" || !strings.Contains(out, "dial failed") {
		t.Fatalf("want status=error with dial failed output, got status=%s out=%s", status, out)
	}
	// The action row itself flipped.
	got, _ := st.GetAIAction(ctx, actID)
	if got.Status != "error" {
		t.Fatalf("action row status want error, got %s", got.Status)
	}

	// Second approve: not pending anymore -> typed error, no re-execution.
	_, _, aerr = srv.ApproveAIAction(ctx, actID, "web")
	if aerr == nil {
		t.Fatalf("second approve: want notPending error, got nil")
	}
	var np *notPendingError
	if !errors.As(aerr, &np) {
		t.Fatalf("want notPendingError, got %T", aerr)
	}

	// Audit recorded the run attempt with the via label (dial failure is audited too).
	var n int
	_ = st.DB.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM audit_log WHERE action='ai_action_run' AND detail LIKE '%via=telegram%'`).Scan(&n)
	if n != 1 {
		t.Fatalf("want 1 ai_action_run audit row via=telegram, got %d", n)
	}

	printIMPFromBuf(t, buf)
}
