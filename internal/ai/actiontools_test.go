package ai

import (
	"context"
	"encoding/json"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/store"
)

// stubExec is a fake ActionExecutor for testing propose_command without SSH.
type stubExec struct {
	called   bool
	lastCmd  string
	out      string
	failWith error
}

func (e *stubExec) Execute(ctx context.Context, vmID int64, command string) (string, error) {
	e.called = true
	e.lastCmd = command
	return e.out, e.failWith
}

// region FUNC_test_ProposeCommand_Pending [DOMAIN(7): Testing; CONCEPT(7]: Actions; TECH(6]: store]
// @purpose Default (no auto-approve): propose_command inserts a pending action and tells the model.
// @complexity 4
// endregion FUNC_test_ProposeCommand_Pending
func TestProposeCommand_Pending(t *testing.T) {
	s := newAIStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "g", Hostname: "10.0.0.9", IP: "10.0.0.9", PortSSH: 22})
	_ = s.SetAIEnabled(ctx, vmID, true) // grant AI access

	exec := &stubExec{out: "should-not-run"}
	reg := NewRegistry(ActionTools(s, exec)...)

	out, err := reg.Run(ctx, "propose_command", map[string]any{
		"vm_id": float64(vmID), "command": "hostname", "reason": "test",
	})
	if err != nil {
		t.Fatalf("propose_command: %v", err)
	}
	if exec.called {
		t.Fatal("executor must NOT run when auto-approve is off")
	}
	var res map[string]any
	_ = json.Unmarshal([]byte(out), &res)
	if res["proposed"] != true {
		t.Fatalf("expected proposed=true, got %s", out)
	}
	if res["action_id"] == nil {
		t.Fatalf("expected action_id, got %s", out)
	}
	// The action must be pending in the store.
	pending, _ := s.ListAIActions(ctx, "pending")
	if len(pending) != 1 || pending[0].Command != "hostname" {
		t.Fatalf("pending action not stored: %+v", pending)
	}
	t.Logf("[IMP:8][TestPropose][PENDING] %s", out)
}

// region FUNC_test_ProposeCommand_NonGranted [DOMAIN(7): Testing; CONCEPT(7]: AccessGate; TECH(5]: store]
// @purpose A VM without ai access must refuse propose_command.
// @complexity 3
// endregion FUNC_test_ProposeCommand_NonGranted
func TestProposeCommand_NonGranted(t *testing.T) {
	s := newAIStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "h", Hostname: "10.0.0.8", IP: "10.0.0.8", PortSSH: 22})
	// NOT granted (ai_enabled=false)
	exec := &stubExec{}
	reg := NewRegistry(ActionTools(s, exec)...)
	out, _ := reg.Run(ctx, "propose_command", map[string]any{"vm_id": float64(vmID), "command": "ls"})
	if !strings.Contains(out, "ai access disabled") {
		t.Fatalf("non-granted VM must be refused, got %s", out)
	}
	if exec.called {
		t.Fatal("executor must not run for non-granted VM")
	}
	t.Logf("[IMP:8][TestPropose][DENIED] %s", out)
}

// region FUNC_test_ProposeCommand_DestructiveBlocked [DOMAIN(7): Testing; CONCEPT(7]: Safety; TECH(4]: store]
// @purpose Even with auto-approve + grant, a destructive command must be refused by the executor
// backstop (this exercises the path via a stub that mimics the refusal).
// @complexity 3
// endregion FUNC_test_ProposeCommand_DestructiveBlocked
func TestProposeCommand_DestructiveBlocked(t *testing.T) {
	// The destructive backstop lives in ssh.IsDestructiveCommand (unit-tested separately). Here we
	// only assert the tool refuses when the executor returns a refusal error, as the real dialer would.
	s := newAIStore(t)
	ctx := context.Background()
	vmID, _ := s.CreateVM(ctx, store.VM{Name: "g", Hostname: "10.0.0.9", IP: "10.0.0.9", PortSSH: 22})
	_ = s.SetAIEnabled(ctx, vmID, true)
	_ = s.SetSetting(ctx, store.SettingAIAutoApprove, "true", false)

	exec := &stubExec{failWith: errRefused("refused: destructive")}
	reg := NewRegistry(ActionTools(s, exec)...)
	out, _ := reg.Run(ctx, "propose_command", map[string]any{"vm_id": float64(vmID), "command": "rm -rf /"})
	var res map[string]any
	_ = json.Unmarshal([]byte(out), &res)
	if res["status"] != "error" {
		t.Fatalf("destructive auto-run must be recorded as error, got %s", out)
	}
	t.Logf("[IMP:8][TestPropose][BLOCKED] %s", out)
}

type errRefused string

func (e errRefused) Error() string { return string(e) }
