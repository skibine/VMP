// Package ai — mutating action tools (Plane B). The model PROPOSES a command; the operator approves
// (or auto-approve executes at once). Read tools are unaffected.
//
// region MODULE_CONTRACT [DOMAIN(9): AI,Security; CONCEPT(8): MutatingActions; TECH(7): store,executor]
// @purpose Let the assistant propose commands on ai-enabled VMs and read back their outcome. By
//
//	default proposals wait for operator approval; when ai_action_auto_approve is set they execute
//	immediately via the executor. A destructive-pattern backstop refuses catastrophic commands.
//
// @invariants
//   - propose_command refuses VMs without ai access or without SSH credentials.
//   - Execution is delegated to an ActionExecutor (the api.Server wires the SSH dialer); the ai
//     package never imports ssh (no cycle).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: propose_command, get_action, mutating, approve, auto_approve, executor, plane b
// STRUCTURE: ▶ ┌{vm,cmd,reason}┐ → 〈ai_enabled?〉 → ◇ auto_approve? exec : INSERT pending → ⎋ message
package ai

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/skibine/vmp/internal/store"
)

// ActionExecutor runs an approved command on a VM (wired by the api layer to the SSH dialer).
type ActionExecutor interface {
	Execute(ctx context.Context, vmID int64, command string) (string, error)
}

// strArg reads a string arg from JSON-decoded map.
func strArg(args map[string]any, key string) (string, bool) {
	if s, ok := args[key].(string); ok {
		return s, true
	}
	return "", false
}

// ActionTools builds the mutating action tools: propose_command and get_action.
func ActionTools(s *store.Store, exec ActionExecutor) []Tool {
	// execBudget bounds silent auto-executions to autoExecPerHour per PROCESS hour. RAM-only:
	// a restart resets it, which is fine - the bound targets runaway agent loops, not humans.
	execBudget := newHourlyBudget(autoExecPerHour)
	return []Tool{
		{
			Name:        "propose_command",
			Description: "Propose a shell command to run on an ai-enabled VM. By default it waits for the operator to approve the action in the UI; if auto-approve is enabled it runs immediately and returns the output. sudo is supported: if the operator stored a sudo password for the VM, prefix the command with `sudo ` (e.g. `sudo apt install -y traceroute`) and it will run non-interactively; without a stored sudo password, `sudo -n` (passwordless) is used.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":   map[string]any{"type": "integer"},
					"command": map[string]any{"type": "string"},
					"reason":  map[string]any{"type": "string"},
				},
				"required": []string{"vm_id", "command"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, ok := intArg(args, "vm_id")
				if !ok {
					return "", fmt.Errorf("vm_id required")
				}
				command, ok := strArg(args, "command")
				if !ok || command == "" {
					return "", fmt.Errorf("command required")
				}
				reason, _ := strArg(args, "reason")
				vm, err := s.GetVM(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": vmID})
				}
				if !vm.AIEnabled {
					return jsonStr(map[string]any{"error": "ai access disabled for this vm", "vm_id": vmID})
				}
				// BUG_FIX_CONTEXT (2026-08-19 audit): auto-approve is the prompt-injection
				// payoff step. Two brakes, both forcing PENDING (operator's ✅/❌) instead of
				// silent execution:
				//   1. this turn ingested untrusted external content (fetched page / whois /
				//      scan banner) - the classic injection carrier;
				//   2. the hourly auto-execution budget is exhausted (bounds any runaway loop).
				suppress := ""
				if ExternalContentSeen(ctx) {
					suppress = "auto-approve suppressed: untrusted external content was fetched in this turn"
				} else if !execBudget.allow() {
					suppress = "auto-approve suppressed: hourly auto-execution budget exhausted"
				}
				if suppress == "" && s.IsAIAutoApprove(ctx) && exec != nil {
					out, runErr := exec.Execute(ctx, vmID, command)
					status := "done"
					if runErr != nil {
						status = "error"
					}
					id, _ := s.CreateAIAction(ctx, store.AIAction{
						VMID: vmID, Command: command, Reason: reason, RequestedBy: "ai",
					})
					_ = s.SetAIActionStatus(ctx, id, status, truncateForStore(out+"\n"+errToStr(runErr)))
					return jsonStr(map[string]any{"executed": true, "status": status, "output": out, "error": errToStr(runErr)})
				}
				if reason == "" && suppress != "" {
					reason = suppress
				} else if suppress != "" {
					reason = suppress + "; " + reason
				}
				id, err := s.CreateAIAction(ctx, store.AIAction{VMID: vmID, Command: command, Reason: reason})
				if err != nil {
					return "", err
				}
				return jsonStr(map[string]any{
					"proposed": true, "action_id": id, "vm_id": vmID, "command": command,
					"message": fmt.Sprintf("Action #%d proposed — awaiting operator approval in the UI.", id),
				})
			},
		},
		{
			Name:        "get_action",
			Description: "Read the status and output of a proposed/executed action by its id (to follow up after approval).",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"action_id": map[string]any{"type": "integer"}},
				"required":   []string{"action_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				id, ok := intArg(args, "action_id")
				if !ok {
					return "", fmt.Errorf("action_id required")
				}
				a, err := s.GetAIAction(ctx, id)
				if err != nil {
					return jsonStr(map[string]any{"error": "action not found", "action_id": id})
				}
				return jsonStr(a)
			},
		},
	}
}

func errToStr(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}

func truncateForStore(s string) string {
	if len(s) > 8000 {
		return s[:8000] + "\n...[truncated]..."
	}
	return s
}

// autoExecPerHour caps silent auto-approved executions per rolling hour (prompt-injection
// blast-radius bound: an injected loop can at worst burn N commands before the operator
// sees a stream of pending ✅/❌ announcements in chat).
const autoExecPerHour = 10

// hourlyBudget is a rolling-window counter.
type hourlyBudget struct {
	mu    sync.Mutex
	times []time.Time
}

func newHourlyBudget(max int) *hourlyBudget {
	return &hourlyBudget{times: make([]time.Time, 0, max)}
}

// allow records an execution slot and reports whether one fits the rolling hour.
func (h *hourlyBudget) allow() bool {
	now := time.Now()
	h.mu.Lock()
	defer h.mu.Unlock()
	kept := h.times[:0]
	for _, t := range h.times {
		if now.Sub(t) < time.Hour {
			kept = append(kept, t)
		}
	}
	if len(kept) >= cap(h.times) {
		h.times = kept
		return false
	}
	h.times = append(kept, now)
	return true
}
