// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8]: Agent; TECH(7]: mock]
// @purpose Verify the agent tool-calling loop: executes a tool call then returns the final
//
//	answer; and that an infinite tool-loop is bounded by MaxIters.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, agent, Ask, mock provider, tool call, max iters
// STRUCTURE: ▶ ┌script[tool_call,answer]┐ → ○ Ask → 〈exec list_vms? answer?〉 → ⎋ assert
package ai

import (
	"bytes"
	"context"
	"log/slog"
	"path/filepath"
	"strings"
	"testing"

	"github.com/skibine/vm-pulse/internal/lddcheck"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// scriptProvider returns scripted responses in order.
type scriptProvider struct {
	responses []ChatResponse
	calls     int
}

func (p *scriptProvider) Chat(_ context.Context, _ ChatRequest) (ChatResponse, error) {
	if len(p.responses) == 0 {
		return ChatResponse{}, nil
	}
	if p.calls >= len(p.responses) {
		// Repeat the last scripted response (used to drive infinite tool-calling in tests).
		return p.responses[len(p.responses)-1], nil
	}
	r := p.responses[p.calls]
	p.calls++
	return r, nil
}

func TestAgent_ToolCallThenAnswer(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)

	s, err := store.Open(filepath.Join(t.TempDir(), "agent.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	_, _ = s.CreateVM(ctx, store.VM{Name: "web1", Hostname: "h", IP: "1.1.1.1", PortSSH: 22})

	prov := &scriptProvider{responses: []ChatResponse{
		{ToolCalls: []ToolCall{{ID: "c1", Type: "function", Function: FunctionCall{Name: "list_vms", Arguments: "{}"}}}},
		{Content: "You have 1 VM named web1."},
	}}
	ag := &Agent{Provider: prov, Tools: NewRegistry(StoreTools(s)...), Model: "m", Logger: logger}

	ans, err := ag.Ask(ctx, "what VMs do I have?", nil)
	if err != nil {
		t.Fatalf("Ask: %v", err)
	}
	if !strings.Contains(ans.Reply, "web1") {
		t.Fatalf("answer should mention web1, got: %s", ans.Reply)
	}
	if prov.calls != 2 {
		t.Fatalf("provider should be called twice, got %d", prov.calls)
	}

	// Semantic Trace: ANSWER anchor present.
	saw := false
	for _, line := range strings.Split(buf.String(), "\n") {
		if imp, ok := lddcheck.IMPValue(line); ok && imp >= 9 && strings.Contains(line, "ANSWER") {
			saw = true
		}
	}
	if !saw {
		t.Error("Anti-Illusion: missing [IMP:9][Ask][ANSWER]")
	}
}

func TestAgent_BoundedLoop(t *testing.T) {
	logger := logging.Setup(slog.LevelDebug, &bytes.Buffer{})
	// Provider always returns a tool call -> must stop at MaxIters.
	prov := &scriptProvider{responses: []ChatResponse{
		{ToolCalls: []ToolCall{{ID: "c1", Type: "function", Function: FunctionCall{Name: "list_vms", Arguments: "{}"}}}},
	}}
	ag := &Agent{Provider: prov, Tools: NewRegistry(Tool{
		Name: "list_vms",
		Run:  func(context.Context, map[string]any) (string, error) { return "[]", nil },
	}), Model: "m", MaxIters: 2, Logger: logger}

	_, err := ag.Ask(context.Background(), "loop", nil)
	if err == nil {
		t.Fatal("expected max-iters error")
	}
}
