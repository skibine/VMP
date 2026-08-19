// Package ai — runtime AI provider backed by the settings store.
//
// region MODULE_CONTRACT [DOMAIN(9): AI; CONCEPT(8): RuntimeProvider; TECH(6): store]
// @purpose Make the AI provider configurable at runtime (Settings UI) without restart. Reads
//
//	the current AI config from the settings store on each call (key decrypted in RAM).
//
// @io Chat(ctx, ChatRequest) -> (ChatResponse, error)
// @invariants
//   - Returns ErrNotConfigured when AI is not fully configured (api_url+api_key+model).
//   - Never caches secrets; reads fresh on each call so Settings updates take effect immediately.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: SettingsProvider, runtime AI, ErrNotConfigured, settings, provider
// STRUCTURE: ▶ ┌req┐ → ○ GetAIConfig → 〈configured?〉 → ⊕ OpenAIProvider.Chat → ⎷
package ai

import (
	"context"
	"errors"

	"github.com/skibine/vmp/internal/store"
)

// ErrNotConfigured is returned when AI settings are incomplete.
var ErrNotConfigured = errors.New("ai: not configured")

// region STRUCT_SettingsProvider [DOMAIN(9): AI; CONCEPT(7): Adapter; TECH(5): struct]
// @purpose A Provider that resolves the real backend from settings on each call.
// endregion STRUCT_SettingsProvider
type SettingsProvider struct {
	Store *store.Store
}

// region FUNC_SettingsProvider_Chat [DOMAIN(9): AI; CONCEPT(7): Resolve; TECH(6): store]
// @purpose Read current AI settings; if configured, delegate to a fresh OpenAIProvider.
// @complexity 4
// endregion FUNC_SettingsProvider_Chat
func (p *SettingsProvider) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	cfg, err := p.Store.GetAIConfig(ctx)
	if err != nil {
		return ChatResponse{}, err
	}
	if !cfg.Configured() {
		return ChatResponse{}, ErrNotConfigured
	}
	if req.Model == "" {
		req.Model = cfg.Model
	}
	return (&OpenAIProvider{APIURL: cfg.APIURL, APIKey: cfg.APIKey}).Chat(ctx, req)
}
