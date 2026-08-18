// Package ai implements the AI copilot layer: an LLM provider abstraction and a tool-calling
// agent over the VM Pulse data.
//
// region MODULE_CONTRACT [DOMAIN(9): AI; CONCEPT(8): Copilot; TECH(8): net/http,tool-calling]
// @purpose Let the user converse with their fleet ("check vm-3", "any alerts?"). v0 is
//
//	READ-ONLY: tools only read Plane A state; mutating actions come in a later slice
//	behind Plane B gating.
//
// @io Provider.Chat(ctx, ChatRequest) -> (ChatResponse, error)
// @invariants
//   - Provider implementations never mutate VM Pulse state.
//   - An empty/missing API key means "AI not configured"; callers must guard.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: AI, LLM, provider, OpenAI, chat, tool call, Message, agent, copilot
// STRUCTURE: ▶ ┌messages+tools┐ → ○ Provider.Chat → 〈tool_calls? loop〉 → ⊕ answer → ⎷
package ai

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// region STRUCT_Message [DOMAIN(8): AI; CONCEPT(7): Chat; TECH(6): struct]
// @purpose One chat message. Marshals directly to the OpenAI-compatible message format.
// endregion STRUCT_Message
type Message struct {
	Role       string     `json:"role"`    // system | user | assistant | tool
	Content    string     `json:"content"` // text — ALWAYS emitted (string), never omitted
	ToolCalls  []ToolCall `json:"tool_calls,omitempty"`
	ToolCallID string     `json:"tool_call_id,omitempty"`
}

// region STRUCT_ToolCall [DOMAIN(8): AI; CONCEPT(7): ToolUse; TECH(6): struct]
// @purpose A tool invocation returned by the model.
// endregion STRUCT_ToolCall
type ToolCall struct {
	ID       string       `json:"id"`
	Type     string       `json:"type"` // "function"
	Function FunctionCall `json:"function"`
}

// FunctionCall carries the function name and a JSON-string of arguments.
type FunctionCall struct {
	Name      string `json:"name"`
	Arguments string `json:"arguments"` // JSON string
}

// ToolFunc executes a tool with parsed JSON arguments, returning a string result.
type ToolFunc func(ctx context.Context, args map[string]any) (string, error)

// region STRUCT_Tool [DOMAIN(8): AI; CONCEPT(7): ToolDef; TECH(6): struct]
// @purpose A tool definition + handler. Run is NOT serialized (only Name/Description/Parameters
//
//	go to the model).
//
// endregion STRUCT_Tool
type Tool struct {
	Name        string
	Description string
	Parameters  map[string]any // JSON schema
	Run         ToolFunc
}

// ChatRequest is the input to Provider.Chat.
type ChatRequest struct {
	Model    string
	Messages []Message
	Tools    []Tool
}

// ChatResponse is the assistant turn.
type ChatResponse struct {
	Content   string
	ToolCalls []ToolCall
}

// region STRUCT_Provider [DOMAIN(8): AI; CONCEPT(8): LLM; TECH(7): interface]
// @purpose Abstraction over an LLM backend. Implementations: OpenAIProvider (and, later, Ollama).
// endregion STRUCT_Provider
type Provider interface {
	Chat(ctx context.Context, req ChatRequest) (ChatResponse, error)
}

// region STRUCT_OpenAIProvider [DOMAIN(8): AI; CONCEPT(7): Backend; TECH(8): net/http]
// @purpose Talks to any OpenAI-compatible /v1/chat/completions endpoint (OpenAI, OpenRouter,
//
//	local servers). HTTP client is injectable for httptest.
//
// endregion STRUCT_OpenAIProvider
type OpenAIProvider struct {
	APIURL string // base, e.g. https://api.openai.com/v1
	APIKey string
	HTTP   *http.Client
}

// llmTimeout picks a generous ceiling for local LLM servers (Ollama/LM Studio/vLLM on localhost):
// their cold start (model load into RAM/VRAM) + CPU inference can take minutes on the first turn,
// which blows past a cloud-tuned 60s. Cloud APIs answer in seconds, so the ceiling never bites them.
func llmTimeout(apiURL string) time.Duration {
	if strings.Contains(apiURL, "127.0.0.1") || strings.Contains(apiURL, "localhost") || strings.Contains(apiURL, "[::1]") {
		return 5 * time.Minute
	}
	return 60 * time.Second
}

// region FUNC_OpenAIProvider_Chat [DOMAIN(8): AI; CONCEPT(7): Call; TECH(8): net/http]
// @purpose POST {APIURL}/chat/completions and parse the assistant turn.
// @complexity 5
// endregion FUNC_OpenAIProvider_Chat
func (p *OpenAIProvider) Chat(ctx context.Context, req ChatRequest) (ChatResponse, error) {
	if p.HTTP == nil {
		p.HTTP = &http.Client{Timeout: llmTimeout(p.APIURL)}
	}
	body := openAIReq{
		Model:      req.Model,
		Messages:   req.Messages,
		Tools:      toSchemaTools(req.Tools),
		ToolChoice: "auto",
	}
	raw, err := json.Marshal(body)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("ai: marshal request: %w", err)
	}
	endpoint := p.APIURL + "/chat/completions"
	httpReq, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint, bytes.NewReader(raw))
	if err != nil {
		return ChatResponse{}, fmt.Errorf("ai: build request: %w", err)
	}
	httpReq.Header.Set("Content-Type", "application/json")
	httpReq.Header.Set("Authorization", "Bearer "+p.APIKey)

	resp, err := p.HTTP.Do(httpReq)
	if err != nil {
		return ChatResponse{}, fmt.Errorf("ai: request: %w", err)
	}
	defer resp.Body.Close()
	respBody, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return ChatResponse{}, fmt.Errorf("ai: api status %d: %s", resp.StatusCode, string(respBody))
	}
	var parsed openAIResp
	if err := json.Unmarshal(respBody, &parsed); err != nil {
		return ChatResponse{}, fmt.Errorf("ai: parse response: %w", err)
	}
	if len(parsed.Choices) == 0 {
		return ChatResponse{}, fmt.Errorf("ai: empty choices")
	}
	ch := parsed.Choices[0].Message
	return ChatResponse{Content: ch.Content, ToolCalls: ch.ToolCalls}, nil
}

// ── OpenAI wire types ───────────────────────────────────────────────────────────────

type openAIReq struct {
	Model      string       `json:"model"`
	Messages   []Message    `json:"messages"`
	Tools      []schemaTool `json:"tools,omitempty"`
	ToolChoice any          `json:"tool_choice,omitempty"`
}

type schemaTool struct {
	Type     string       `json:"type"` // "function"
	Function schemaToolFn `json:"function"`
}

type schemaToolFn struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	Parameters  map[string]any `json:"parameters"`
}

type openAIResp struct {
	Choices []struct {
		Message struct {
			Role      string     `json:"role"`
			Content   string     `json:"content"`
			ToolCalls []ToolCall `json:"tool_calls"`
		} `json:"message"`
	} `json:"choices"`
}

// toSchemaTools strips the Run handler (not serializable) and keeps the schema fields.
func toSchemaTools(tools []Tool) []schemaTool {
	out := make([]schemaTool, 0, len(tools))
	for _, t := range tools {
		params := t.Parameters
		if params == nil {
			params = map[string]any{"type": "object", "properties": map[string]any{}}
		}
		out = append(out, schemaTool{
			Type:     "function",
			Function: schemaToolFn{Name: t.Name, Description: t.Description, Parameters: params},
		})
	}
	return out
}
