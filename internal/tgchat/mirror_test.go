// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): WebToTelegramMirror; TECH(8): go test]
// @purpose Verify the web->telegram half of the shared conversation: Manager.MirrorWebTurn relays
//
//	a completed web chat turn (and its pending actions) to every active bridge chat, and is a
//	no-op when no telegram channel has agent_chat_enabled on.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, mirror, web turn, telegram relay, manager, fanout, no-op
// STRUCTURE: ▶ ┌store+channel+fakeBot┐ → ▶ Manager.Run → ○ MirrorWebTurn → 〈fakeBot.sent ∋ 🌐?〉
package tgchat

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skibine/vmp/internal/store"
)

// region FUNC_test_ManagerMirror [DOMAIN(7): Testing; CONCEPT(8): MirrorFanout; TECH(7): httptest]
// @purpose End-to-end: a channel-driven manager mirrors a web turn into the bot's chat; a manager
//
//	with NO active bridges (agent_chat_enabled off) silently drops the same call.
//
// @complexity 5
// endregion FUNC_test_ManagerMirror
func TestManager_MirrorWebTurn(t *testing.T) {
	fb := &fakeBot{}
	srv := httptest.NewServer(http.HandlerFunc(fb.handler))
	t.Cleanup(srv.Close)

	st, err := store.Open(t.TempDir()+"/mirror.sqlite", nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	m := &Manager{Store: st, Agent: &mockAsker{reply: "ok"}, Approver: &fakeApprover{},
		ResyncEvery: 40 * time.Millisecond}

	// No channels yet: mirror must be a silent no-op.
	m.MirrorWebTurn(ctx, "q-before", "a-before", 0)

	// Enable a telegram bridge pointed at the fake Bot API.
	if _, err := st.CreateChannel(ctx, store.Channel{
		Type: "telegram", Name: "op", Enabled: true,
		Config: map[string]any{
			"bot_token": "111:TEST", "chat_id": "42",
			"agent_chat_enabled": true, "api_url": srv.URL,
		},
	}); err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}

	go m.Run(ctx)

	// Wait for the resync to start the poller (bounded).
	deadline := time.Now().Add(3 * time.Second)
	started := false
	for time.Now().Before(deadline) {
		fb.mu.Lock()
		n := len(fb.sent)
		fb.mu.Unlock()
		_ = n
		m.mu.Lock()
		started = len(m.current) > 0
		m.mu.Unlock()
		if started {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !started {
		t.Fatal("manager did not start the poller in time")
	}
	// Let the poller's long-poll settle so getUpdates noise doesn't interleave.
	time.Sleep(100 * time.Millisecond)

	m.MirrorWebTurn(ctx, "что с web1?", "всё работает", 0)

	deadline = time.Now().Add(3 * time.Second)
	found := false
	for time.Now().Before(deadline) {
		fb.mu.Lock()
		sent := append([]string(nil), fb.sent...)
		fb.mu.Unlock()
		for _, s := range sent {
			if strings.Contains(s, "что с web1?") && strings.Contains(s, "всё работает") {
				found = true
			}
		}
		if found {
			break
		}
		time.Sleep(20 * time.Millisecond)
	}
	if !found {
		t.Fatal("mirrored web turn not sent to the bot chat")
	}
	t.Logf("[IMP:8][TestMirror][RESULT] web turn relayed to telegram chat 42")
}

// region FUNC_test_ManagerMirrorNoop [DOMAIN(6): Testing; CONCEPT(6): NoopSafety; TECH(4): mutex]
// @purpose Without agent_chat_enabled the manager has zero loops and MirrorWebTurn returns fast.
// @complexity 2
// endregion FUNC_test_ManagerMirrorNoop
func TestManager_MirrorWebTurn_NoopWithoutBridges(t *testing.T) {
	var once sync.Once
	st, err := store.Open(t.TempDir()+"/noop.sqlite", nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	m := &Manager{Store: st, Agent: &mockAsker{reply: "ok"}, Approver: &fakeApprover{},
		ResyncEvery: 50 * time.Millisecond}
	go m.Run(ctx)
	time.Sleep(150 * time.Millisecond) // resync runs with zero channels
	done := make(chan struct{})
	go func() { defer close(done); m.MirrorWebTurn(ctx, "q", "a", 0) }()
	select {
	case <-done:
		once.Do(func() { t.Logf("[IMP:8][TestMirrorNoop][RESULT] no-op fast return") })
	case <-time.After(2 * time.Second):
		t.Fatal("MirrorWebTurn must not block without bridges")
	}
}

// endregion FUNC_test_ManagerMirror
