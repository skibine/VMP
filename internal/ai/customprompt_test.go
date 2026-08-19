// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): CustomSystemPrompt; TECH(8): go test]
// @purpose Operator system prompt: append layers over the safety baseline, replace swaps it.
// GREP_SUMMARY: test, system prompt, custom, append, replace, agent
package ai

import (
	"context"
	"testing"
)

func TestAgent_SystemPromptCustom(t *testing.T) {
	a := &Agent{CustomPrompt: func(ctx context.Context) (string, string) {
		return "append", "Always answer in haiku."
	}}
	got := a.systemPrompt(context.Background())
	if got == "Always answer in haiku." {
		t.Fatal("append must KEEP the built-in baseline")
	}
	if !contains(got, "OPERATOR SYSTEM PROMPT") || !contains(got, "Always answer in haiku.") {
		t.Fatal("append must include the custom text with a marker")
	}
	t.Logf("[IMP:8][TestSP][RESULT] append ok (len=%d)", len(got))

	a2 := &Agent{CustomPrompt: func(ctx context.Context) (string, string) {
		return "replace", "You are a pirate."
	}}
	if got2 := a2.systemPrompt(context.Background()); got2 != "You are a pirate." {
		t.Fatalf("replace must swap entirely, got %.60s", got2)
	}
	// Empty custom text -> pure baseline (unset setting).
	a3 := &Agent{CustomPrompt: func(ctx context.Context) (string, string) { return "append", "  " }}
	if got3 := a3.systemPrompt(context.Background()); contains(got3, "OPERATOR SYSTEM PROMPT") {
		t.Fatal("blank custom text must be ignored")
	}
	t.Logf("[IMP:9][TestSP][RESULT] replace + blank ok")
}

func contains(s, sub string) bool {
	return len(s) >= len(sub) && (func() bool {
		for i := 0; i+len(sub) <= len(s); i++ {
			if s[i:i+len(sub)] == sub {
				return true
			}
		}
		return false
	})()
}
