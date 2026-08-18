// Package tgchat — manager: owns the poller set, resynced from the channels table.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Integration; CONCEPT(7): Lifecycle; TECH(7): goroutines]
// @purpose Keep exactly one long-poll loop per bot TOKEN whose channel has agent_chat_enabled on,
//
//	starting/stopping pollers as the operator edits channels in Settings — no restart needed.
//
// @invariants
//   - Pollers are keyed by bot_token (NOT channel id): one token shared by two channels yields ONE
//     poller with a merged chat allowlist — two loops on one token would 409-war each other.
//   - A channel edit (chat_id added/removed) restarts that token's poller with the fresh allowlist.
//   - Manager.Run returns only when ctx is cancelled; every poller exits with it.
//
// @rationale
// Q: Why resync every 30s instead of watching a change feed?
// A: The channels table is small and edited by hand; polling ListChannels twice a minute is
//
//	negligible next to the long-poll loops themselves and needs zero new plumbing.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: manager, resync, channels, poller lifecycle, bot_token, allowlist, agent_chat_enabled
// STRUCTURE: ▶ ○ tick 30s → ○ ListChannels → ◇ agent_chat_enabled? → ⊕ wantSet keyed token → 〈diff curSet〉 → ▶ start / ⏹ stop → ⎋
package tgchat

import (
	"context"
	"log/slog"
	"strconv"
	"time"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// Manager supervises the Telegram chat pollers.
type Manager struct {
	Store    *store.Store
	Agent    Asker
	Approver Approver
	Logger   *slog.Logger

	ResyncEvery time.Duration // test hook; default 30s
}

// region FUNC_Manager_Run [DOMAIN(8): Integration; CONCEPT(7): Supervise; TECH(7): goroutines]
// @purpose Resync pollers from the channels table every ResyncEvery until ctx is done.
// @complexity 6
// endregion FUNC_Manager_Run
func (m *Manager) Run(ctx context.Context) {
	type loop struct {
		cancel  context.CancelFunc
		chatIDs map[string]bool
		apiBase string
	}
	current := map[string]*loop{} // bot_token -> running poller

	type wantEntry struct {
		chats   map[string]bool
		apiBase string // from channel config api_url (tests); empty = official Bot API
	}
	resync := func() {
		want := map[string]*wantEntry{} // token -> merged entry
		channels, err := m.Store.ListChannels(ctx)
		if err != nil {
			logging.LDD(m.Logger, 8, "tgchat", "RESYNC_FAIL", err.Error())
			return
		}
		for _, ch := range channels {
			if ch.Type != "telegram" || !ch.Enabled {
				continue
			}
			if !configBool(ch.Config, "agent_chat_enabled") {
				continue
			}
			token := configStr(ch.Config, "bot_token")
			chatID := configStr(ch.Config, "chat_id")
			if token == "" || chatID == "" {
				continue
			}
			e := want[token]
			if e == nil {
				e = &wantEntry{chats: map[string]bool{}}
				want[token] = e
			}
			e.chats[chatID] = true
			if u := configStr(ch.Config, "api_url"); u != "" {
				e.apiBase = u
			}
		}

		// Stop removed/changed pollers.
		for token, lp := range current {
			w, still := want[token]
			if still && sameChats(lp.chatIDs, w.chats) && lp.apiBase == w.apiBase {
				continue
			}
			lp.cancel()
			delete(current, token)
			logging.LDD(m.Logger, 7, "tgchat", "POLL_STOP", "token=***")
		}
		// Start new ones (or restarted ones with a changed allowlist).
		for token, w := range want {
			if _, running := current[token]; running {
				continue
			}
			pctx, cancel := context.WithCancel(ctx)
			chatIDs := map[string]bool{}
			for c := range w.chats {
				chatIDs[c] = true
			}
			go (&poller{
				api:      newBotAPI(token, w.apiBase),
				allowed:  chatIDs,
				st:       m.Store,
				agent:    m.Agent,
				approver: m.Approver,
				logger:   m.Logger,
			}).run(pctx)
			current[token] = &loop{cancel: cancel, chatIDs: chatIDs, apiBase: w.apiBase}
			logging.LDD(m.Logger, 7, "tgchat", "POLL_START", "bot bridge started, chats="+strconv.Itoa(len(chatIDs)))
			_ = audit.Append(m.Store.DB, m.Logger, audit.Entry{
				Plane: audit.PlaneB, Action: "tg_chat_start", Success: true,
				Detail: "chats=" + strconv.Itoa(len(chatIDs)),
			})
		}
	}

	resync()
	interval := m.ResyncEvery
	if interval <= 0 {
		interval = 30 * time.Second
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-t.C:
			resync()
		case <-ctx.Done():
			for _, lp := range current {
				lp.cancel()
			}
			return
		}
	}
}

// sameChats compares two chat-id sets.
func sameChats(a, b map[string]bool) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if !b[k] {
			return false
		}
	}
	return true
}

// configStr reads a string from a channel config map.
func configStr(cfg map[string]any, key string) string {
	if cfg == nil {
		return ""
	}
	if s, ok := cfg[key].(string); ok {
		return s
	}
	return ""
}

// configBool reads a bool from a channel config map (accepts bool or "true"/"1" strings).
func configBool(cfg map[string]any, key string) bool {
	if cfg == nil {
		return false
	}
	switch v := cfg[key].(type) {
	case bool:
		return v
	case string:
		return v == "true" || v == "1"
	}
	return false
}
