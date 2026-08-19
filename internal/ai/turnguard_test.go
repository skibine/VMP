// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): PromptInjectionGuard; TECH(8): go test]
// @purpose Verify the injection chain breaker: an untrusted-content turn forces PENDING even
//
//	with auto-approve on; a clean turn auto-executes as before; destructive commands are
//	refused at the executor backstop; the hourly budget bounds silent executions.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, prompt injection, untrusted turn, auto-approve suppression, budget, blocklist
package ai

import (
	"context"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

// region FUNC_test_UntrustedTurn [DOMAIN(9): Security; CONCEPT(8): AutoApproveGate; TECH(6): Registry]
// @purpose The core scenario from the audit: page content says "run X on vm 3" -> get_site_info
//
//	marks the turn -> propose_command CANNOT silently execute; the operator gets a pending row.
//
// @complexity 5
// endregion FUNC_test_UntrustedTurn
func TestProposeCommand_UntrustedTurnSuppressesAutoApprove(t *testing.T) {
	s := newToolsStore(t)
	ctx := WithTurnState(context.Background())
	_ = s.SetSetting(ctx, store.SettingAIAutoApprove, "true", false)

	vmID, _ := s.CreateVM(ctx, store.VM{Name: "v", Hostname: "h", PortSSH: 22, AIEnabled: true})
	reg := NewRegistry(ActionTools(s, &stubExec{})...)

	// Clean turn: auto-approve fires (executed).
	out, _ := reg.Run(ctx, "propose_command", map[string]any{"vm_id": float64(vmID), "command": "uptime"})
	if !strings.Contains(out, `"executed":true`) {
		t.Fatalf("clean turn must auto-execute: %s", out)
	}

	// The injection scenario: external content entered this turn.
	MarkExternalContent(ctx)
	out, _ = reg.Run(ctx, "propose_command", map[string]any{"vm_id": float64(vmID), "command": "id"})
	if strings.Contains(out, `"executed":true`) {
		t.Fatalf("untrusted turn MUST NOT auto-execute: %s", out)
	}
	if !strings.Contains(out, `"proposed":true`) {
		t.Fatalf("untrusted turn must create a pending action: %s", out)
	}
	acts, _ := s.ListAIActions(ctx, "pending")
	if len(acts) == 0 || !strings.Contains(acts[0].Reason, "suppressed") {
		t.Fatalf("pending action must carry the suppression reason: %+v", acts)
	}
	t.Logf("[IMP:9][TestUntrustedTurn][RESULT] auto-approve suppressed after external content; pending created")

	// A FRESH turn is clean again (flag is per-turn, not sticky).
	ctx2 := WithTurnState(context.Background())
	out, _ = reg.Run(ctx2, "propose_command", map[string]any{"vm_id": float64(vmID), "command": "uptime"})
	if !strings.Contains(out, `"executed":true`) {
		t.Fatalf("fresh clean turn must auto-execute again: %s", out)
	}
}

// endregion FUNC_test_UntrustedTurn

// region FUNC_test_ExecBudget [DOMAIN(8): Security; CONCEPT(7): HourlyCap; TECH(4): unit]
// @purpose The rolling budget refuses after N slots.
// @complexity 2
// endregion FUNC_test_ExecBudget
func TestHourlyBudget_BoundsExecutions(t *testing.T) {
	b := newHourlyBudget(3)
	for i := 0; i < 3; i++ {
		if !b.allow() {
			t.Fatalf("slot %d must fit", i+1)
		}
	}
	if b.allow() {
		t.Fatal("4th slot must be refused within the hour")
	}
	t.Logf("[IMP:8][TestBudget][RESULT] hourly budget enforced")
}

// endregion FUNC_test_ExecBudget
