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

	"github.com/skibine/vmp/internal/logging"
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

	// CustomPrompt, when wired (main reads the ai_system_prompt* settings), layers the
	// operator's prompt on top of the built-in one: mode "append" keeps the safety baseline,
	// mode "replace" swaps it entirely (the operator's instance, the operator's call).
	CustomPrompt func(ctx context.Context) (mode, text string)
}

func (a *Agent) maxIters() int {
	if a.MaxIters <= 0 {
		return 12
	}
	return a.MaxIters
}

func (a *Agent) systemPrompt(ctx context.Context) string {
	base := a.builtinPrompt()
	if a.CustomPrompt != nil {
		mode, text := a.CustomPrompt(ctx)
		text = strings.TrimSpace(text)
		if text != "" {
			if mode == "replace" {
				return text
			}
			return base + "\n\n# OPERATOR SYSTEM PROMPT (custom, appended)\n" + text
		}
	}
	return base
}

func (a *Agent) builtinPrompt() string {
	if strings.TrimSpace(a.SystemPrompt) != "" {
		return a.SystemPrompt
	}
	return "You are VMPilot, the AI assistant for a small fleet of virtual machines. " +
		"Use the provided tools to inspect the fleet (VMs, health, check results, alerts) and " +
		"answer concisely. If a tool returns an error, report it plainly. Do not invent data.\n\n" +
		"Answer in the user's language (Russian messages get Russian answers, English get English).\n\n" +
		"Targets: besides servers, EQUIPMENT is supported — routers, cameras, external web panels " +
		"are added via add_vm with kind=equipment (NOT as domains; a bare IP is never a domain). " +
		"They get the same liveness/exposures monitoring; SSH credentials stay optional and " +
		"web-only.\n\n" +
		"Domains: list_domains shows every monitored domain with the latest stored whois/tls/dns " +
		"check statuses; get_domain_info runs a live DNS+TLS+whois probe of one domain (use it for " +
		"'when does the certificate/registration expire' questions). add_vm and add_domain put a " +
		"new server or domain on monitoring immediately — use them for 'поставь на мониторинг'/" +
		"'add to monitoring' requests; they never touch credentials (those are added in the web UI).\n\n" +
		"Fleet config: checks and alert rules are full CRUD — list_checks / add_check / " +
		"update_check / delete_check (system checks are refused), run_check_now for a live run, " +
		"create_alert_rule / delete_alert_rule, ensure_liveness_rule as the covering shortcut. " +
		"Domains: update_domain (toggles, notify thresholds, rename to fix a typo), " +
		"delete_domain (confirm-gated), list/add/delete_domain_reminder, " +
		"acknowledge_dns_change (only after the operator confirms the change is expected). " +
		"Deleting easily-recreatable objects (checks, rules, reminders) is allowed — but ALWAYS " +
		"confirm with the user in chat before a delete. VM config: update_vm also fixes hostname/" +
		"ip/port_ssh (wrong-address incidents; the liveness probe re-targets automatically) on top " +
		"of metadata (name/tags/notes/provider/location/cost + alert_muted / metrics_enabled " +
		"folds). archive_vm takes a VM off monitoring but keeps history; delete_vm wipes the VM and " +
		"ALL its history and REFUSES without confirm='yes' — same confirm gate for delete_domain. " +
		"Prefer fixing (update_vm) over deleting; prefer archive over delete.\n\n" +
		"VM diagnostics: diagnose_vm (ad-hoc probe), scan_vm_ports (fast/full), scan_vm_exposures " +
		"(security, persists), get_site_info, get_vm_metrics (stored series) — all credential-free. " +
		"SSH-based reads (get_vm_snapshot, get_vm_errors, get_vm_updates, refresh_vm_inventory, " +
		"get_vm_vhosts) require the VM to have ai_access + stored credentials; report the gap " +
		"plainly when they refuse.\n\n" +
		"Alerts setup ('поставь оповещения на <vm>' / 'set up alerts'): delivery is PER-SERVER — a " +
		"VM's alerts go to the channels attached to that VM. The full recipe: 1) list_channels, " +
		"2) ensure_liveness_rule(vm_id) so a rule covers the VM, 3) set_vm_alert_channels(vm_id, " +
		"[channel names]) — e.g. the operator's telegram channel and/or 'in-app (bell)'. All three " +
		"steps together complete the setup; report which channels were attached.\n\n" +
		"Web-only (tell the user to use the web UI): deleting/archiving VMs and domains, " +
		"SSH credentials, delivery channel secrets (tokens/urls), 2FA/password changes, AI provider " +
		"settings, the ai_access toggle, and the web terminal.\n\n" +
		"Reachability / 'ping': use probe_host to check ANY target (a VM IP, a domain, an external host) " +
		"directly from the VM Pulse host — NO VM credentials and NO ai_access needed. It TCP-scans common " +
		"ports (22/80/443/...) and runs a security exposure scan; if a port answers, the host is UP. " +
		"Prefer probe_host over trying to run ping/traceroute over SSH — it works even when no VM has access.\n\n" +
		"Visibility model: list_vms and get_vm_health show the WHOLE fleet (every VM's id, name, " +
		"IP and liveness). ai_access on a VM gates only command execution and deep data " +
		"(inventory/results) — you may target any VM's IP from a VM you have ai_access to " +
		"(e.g. run `traceroute <other-vm-ip>` from a granted VM). To run commands ON a VM, it must have " +
		"ai_access=true."
}

// region FUNC_Ask [DOMAIN(9): AI; CONCEPT(8): Converse; TECH(7): loop]
// @purpose Run one user turn to completion, executing tool calls along the way. Returns the final
//
//	reply plus a trace of the tool calls made (so the UI can show what the assistant did).
//
// @complexity 6
// endregion FUNC_Ask
func (a *Agent) Ask(ctx context.Context, message string, history []Message) (AskReply, error) {
	msgs := []Message{{Role: "system", Content: a.systemPrompt(ctx)}}
	msgs = append(msgs, history...)
	msgs = append(msgs, Message{Role: "user", Content: message})

	reply := AskReply{Trace: []TraceStep{}}
	// Fresh per-turn trust state: tools that ingest external content mark it, propose_command
	// consults it (auto-approve suppression - the prompt-injection chain breaker).
	ctx = WithTurnState(ctx)
	logging.LDD(a.Logger, 8, "Ask", "USER", truncate(message, 120))
	for i := 0; i < a.maxIters(); i++ {
		resp, err := a.Provider.Chat(ctx, ChatRequest{Model: a.Model, Messages: msgs, Tools: a.Tools.Tools()})
		if err != nil {
			logging.LDD(a.Logger, 10, "Ask", "CHAT_FAIL", err.Error())
			return reply, err
		}
		if len(resp.ToolCalls) == 0 {
			logging.LDD(a.Logger, 9, "Ask", "ANSWER", truncate(resp.Content, 160))
			reply.Reply = resp.Content
			return reply, nil
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
			reply.Trace = append(reply.Trace, TraceStep{
				Tool: tc.Function.Name, Args: truncate(tc.Function.Arguments, 160), Result: truncate(result, 200),
			})
		}
	}
	logging.LDD(a.Logger, 9, "Ask", "MAX_ITERS", "loop exceeded")
	// Graceful stop instead of a hard error: summarize what was attempted so the user sees progress,
	// not a cryptic 502. The trace carries the tool calls already made.
	steps := make([]string, 0, len(reply.Trace))
	for _, t := range reply.Trace {
		steps = append(steps, t.Tool)
	}
	reply.Reply = fmt.Sprintf("I hit my step limit (%d) before finishing. Steps attempted: %s. "+
		"Please rephrase or ask me to continue.", a.maxIters(), joinOrNone(steps))
	return reply, nil
}

// joinOrNone renders a short tool list (or "none").
func joinOrNone(steps []string) string {
	if len(steps) == 0 {
		return "none"
	}
	return strings.Join(steps, ", ")
}

// AskReply is the result of one turn: the assistant's text + a trace of tool calls it made.
type AskReply struct {
	Reply string      `json:"reply"`
	Trace []TraceStep `json:"trace"`
}

// TraceStep is one tool invocation the assistant performed during a turn.
type TraceStep struct {
	Tool   string `json:"tool"`
	Args   string `json:"args"`
	Result string `json:"result"`
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
