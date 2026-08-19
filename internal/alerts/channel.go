// Package alerts implements alert evaluation and multi-channel delivery (Plane A).
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(8): Channels; TECH(8): net/http]
// @purpose Define the Channel abstraction so new delivery types (telegram/email/webhook)
//
//	plug in without touching the evaluator. Implementations are stateless; per-channel
//	config (bot token, chat id, ...) comes from the DB row at delivery time.
//
// @invariants
//   - A Channel NEVER panics; delivery failures return an error (recorded in delivery_log).
//   - Plane A: delivery uses channel secrets only, never VM SSH credentials.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: alerts, Channel, Message, Registry, LogChannel, delivery, telegram, webhook
// STRUCTURE: ▶ ┌Message┐ → ○ Registry.Get(type) → ⚡ Deliver(config,msg) → 〈ok? log〉 → ⎷
package alerts

import (
	"context"
	"log/slog"
	"sync"

	"github.com/skibine/vmp/internal/logging"
)

// region STRUCT_Message [DOMAIN(7): Alerting; CONCEPT(7): Payload; TECH(5): struct]
// @purpose The normalized payload delivered to every channel for one fired alert.
// endregion STRUCT_Message
type Message struct {
	Severity  string // warning | critical
	RuleName  string
	CheckID   int64
	CheckType string
	VMID      *int64
	Title     string
	Body      string
}

// region STRUCT_Channel [DOMAIN(8): Alerting; CONCEPT(8): Plugin; TECH(7): interface]
// @purpose A delivery type. Stateless; config is supplied per-call from the channel DB row.
// endregion STRUCT_Channel
type Channel interface {
	Type() string
	Deliver(ctx context.Context, config map[string]any, msg Message) error
}

// region STRUCT_Registry [DOMAIN(7): Alerting; CONCEPT(7): PluginRegistry; TECH(6): map]
// @purpose Map channel type -> Channel implementation.
// endregion STRUCT_Registry
type Registry struct {
	mu sync.RWMutex
	m  map[string]Channel
}

func NewRegistry(channels ...Channel) *Registry {
	r := &Registry{m: make(map[string]Channel, len(channels))}
	for _, c := range channels {
		r.Register(c)
	}
	return r
}

func (r *Registry) Register(c Channel) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.m[c.Type()] = c
}

func (r *Registry) Get(t string) (Channel, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	c, ok := r.m[t]
	return c, ok
}

// region STRUCT_LogChannel [DOMAIN(6): Alerting; CONCEPT(6): DevChannel; TECH(6): slog]
// @purpose Always-on dev channel: writes the alert to the log. Useful for local/no-token setup.
// endregion STRUCT_LogChannel
type LogChannel struct {
	Logger *slog.Logger
}

func (LogChannel) Type() string { return "log" }

// region FUNC_LogChannel_Deliver [DOMAIN(6): Alerting; CONCEPT(6): Deliver; TECH(5): slog]
// @purpose Emit the alert as a WARN LDD line so it is visible in Semantic Trace.
// @complexity 2
// endregion FUNC_LogChannel_Deliver
func (c LogChannel) Deliver(ctx context.Context, config map[string]any, msg Message) error {
	logger := c.Logger
	if logger == nil {
		logger = slog.Default()
	}
	logging.LDD(logger, 9, "LogChannel", "DELIVERED", msg.Title+": "+msg.Body)
	return nil
}

// DefaultRegistry returns the built-in channel implementations (log + telegram + webhook).
func DefaultRegistry(logger *slog.Logger) *Registry {
	return NewRegistry(LogChannel{Logger: logger}, &TelegramChannel{}, &WebhookChannel{})
}
