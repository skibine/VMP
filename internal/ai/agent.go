// Package ai — tool-calling agent (ReAct loop).
//
// region MODULE_CONTRACT [DOMAIN(9): AI; CONCEPT(8): Agent; TECH(7): loop]
// @purpose Drive a multi-turn tool-calling conversation: send messages+tools to the LLM,
//
//	execute any returned tool calls, feed results back, until a final text answer.
//
// @io Ask(ctx, message, history) -> (answer, error)
// @invariants
//   - v0 is read-only: the agent can only invoke registry tools (all read-only here).
//   - The loop is bounded by MaxIters (prevents runaway).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: agent, Ask, tool call, ReAct, loop, answer, copilot
// STRUCTURE: ▶ ┌msg+history┐ → ○ Chat → 〈tool_calls? run+append〉 → ⊕ answer → ⎋
package ai

import (
	"context"
	"encoding/json"
	"fmt"
	"log/slog"
	"strings"

	"github.com/skibine/vm-pulse/internal/logging"
)

// region STRUCT_Agent [DOMAIN(9): AI; CONCEPT(7): Orchestrator; TECH(6): struct]
// @purpose Hold the provider, tool registry and tuning for the conversation loop.
// endregion STRUCT_Agent
type Agent struct {
	Provider     Provider
	Tools        *Registry
	Model        string
	MaxIters     int
	Logger       *slog.Logger
	SystemPrompt string
}

func (a *Agent) maxIters() int {
	if a.MaxIters <= 0 {
		return 6
	}
	return a.MaxIters
}

func (a *Agent) systemPrompt() string {
	if strings.TrimSpace(a.SystemPrompt) != "" {
		return a.SystemPrompt
	}
	return "You are VM Pulse, an AI copilot for a small fleet of virtual machines. " +
		"Use the provided tools to inspect the fleet (VMs, health, check results, alerts) and " +
		"answer concisely. If a tool returns an error, report it plainly. Do not invent data."
}

// region FUNC_Ask [DOMAIN(9): AI; CONCEPT(8): Converse; TECH(7): loop]
// @purpose Run one user turn to completion, executing tool calls along the way.
// @complexity 6
// endregion FUNC_Ask
func (a *Agent) Ask(ctx context.Context, message string, history []Message) (string, error) {
	msgs := []Message{{Role: "system", Content: a.systemPrompt()}}
	msgs = append(msgs, history...)
	msgs = append(msgs, Message{Role: "user", Content: message})

	logging.LDD(a.Logger, 8, "Ask", "USER", truncate(message, 120))
	for i := 0; i < a.maxIters(); i++ {
		resp, err := a.Provider.Chat(ctx, ChatRequest{Model: a.Model, Messages: msgs, Tools: a.Tools.Tools()})
		if err != nil {
			logging.LDD(a.Logger, 10, "Ask", "CHAT_FAIL", err.Error())
			return "", err
		}
		if len(resp.ToolCalls) == 0 {
			logging.LDD(a.Logger, 9, "Ask", "ANSWER", truncate(resp.Content, 160))
			return resp.Content, nil
		}
		// Record the assistant's tool invocations, then execute and append results.
		msgs = append(msgs, Message{Role: "assistant", ToolCalls: resp.ToolCalls})
		for _, tc := range resp.ToolCalls {
			args := parseArgs(tc.Function.Arguments)
			result, rerr := a.Tools.Run(ctx, tc.Function.Name, args)
			if rerr != nil {
				result = "error: " + rerr.Error()
			}
			logging.LDD(a.Logger, 8, "Ask", "TOOL", tc.Function.Name+" -> "+truncate(result, 120))
			msgs = append(msgs, Message{Role: "tool", ToolCallID: tc.ID, Content: result})
		}
	}
	logging.LDD(a.Logger, 9, "Ask", "MAX_ITERS", "loop exceeded")
	return "", fmt.Errorf("ai: exceeded %d iterations without a final answer", a.maxIters())
}

// parseArgs unmarshals the tool arguments JSON string; tolerant of empty/invalid input.
func parseArgs(s string) map[string]any {
	out := map[string]any{}
	if strings.TrimSpace(s) == "" {
		return out
	}
	_ = json.Unmarshal([]byte(s), &out)
	return out
}

// truncate clips a string for log readability.
func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n] + "..."
}
