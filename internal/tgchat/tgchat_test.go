// region MODULE_CONTRACT_test [DOMAIN(7): Testing; CONCEPT(8): TelegramChat; TECH(8): go test,httptest]
// @purpose Verify the Telegram bridge end-to-end against a fake Bot API: chat turn through the
//
//	agent (mock provider), allowlist denial + audit, ✅ button executes via the Approver,
//	not-pending callback is graceful, long replies are split, 409 is detected.
//
// endregion MODULE_CONTRACT_test
// GREP_SUMMARY: test, tgchat, poller, fake bot api, httptest, callback, approve, allowlist, split
// STRUCTURE: ▶ ┌fakeAPI┐ → ○ poller.dispatch(message) → ⚡ Ask(mock) → 〈sendMessage captured?〉 → ⚡ callback → ◇ Approver → ⎋
package tgchat

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/skibine/vm-pulse/internal/ai"
	"github.com/skibine/vm-pulse/internal/store"
)

// fakeBot is an httptest Bot API: it records every sendMessage/edit/answer call and can hand
// queued updates to getUpdates.
type fakeBot struct {
	mu       sync.Mutex
	sent     []string // sendMessage bodies
	edits    []string // editMessageText bodies
	answers  []string // answerCallbackQuery texts
	markups  []string // sendMessage reply_markup payloads
	updates  []tgUpdate
	nextID   int64
	conflict bool // when true, getUpdates answers 409
	approver *fakeApprover
}

func (f *fakeBot) handler(w http.ResponseWriter, r *http.Request) {
	b, _ := io.ReadAll(r.Body)
	path := r.URL.Path
	switch {
	case strings.Contains(path, "/getUpdates"):
		f.mu.Lock()
		if f.conflict {
			f.mu.Unlock()
			w.WriteHeader(http.StatusConflict)
			_, _ = w.Write([]byte(`{"ok":false,"description":"Conflict: terminated by other getUpdates request"}`))
			return
		}
		var out []tgUpdate
		if strings.Contains(r.URL.RawQuery, "offset=-1") {
			// Backlog preview: return only the LAST queued update.
			if len(f.updates) > 0 {
				out = f.updates[len(f.updates)-1:]
			}
		} else {
			offset := int64(0)
			for _, kv := range strings.Split(r.URL.RawQuery, "&") {
				if strings.HasPrefix(kv, "offset=") {
					offset, _ = strconv.ParseInt(strings.TrimPrefix(kv, "offset="), 10, 64)
				}
			}
			for _, u := range f.updates {
				if u.UpdateID >= offset {
					out = append(out, u)
				}
			}
			if len(out) > 0 {
				// Confirm consumption: drop everything below the returned max.
				maxID := out[len(out)-1].UpdateID
				kept := f.updates[:0]
				for _, u := range f.updates {
					if u.UpdateID > maxID {
						kept = append(kept, u)
					}
				}
				f.updates = kept
			}
		}
		f.mu.Unlock()
		f.replyJSON(w, map[string]any{"ok": true, "result": out})
	case strings.Contains(path, "/sendMessage"):
		form, _ := url.ParseQuery(string(b))
		f.mu.Lock()
		f.sent = append(f.sent, form.Get("text"))
		f.markups = append(f.markups, form.Get("reply_markup"))
		f.mu.Unlock()
		f.replyJSON(w, map[string]any{"ok": true, "result": map[string]any{"message_id": 777}})
	case strings.Contains(path, "/editMessageText"):
		form, _ := url.ParseQuery(string(b))
		f.mu.Lock()
		f.edits = append(f.edits, form.Get("text"))
		f.mu.Unlock()
		f.replyJSON(w, map[string]any{"ok": true, "result": true})
	case strings.Contains(path, "/answerCallbackQuery"):
		form, _ := url.ParseQuery(string(b))
		f.mu.Lock()
		f.answers = append(f.answers, form.Get("text"))
		f.mu.Unlock()
		f.replyJSON(w, map[string]any{"ok": true, "result": true})
	default:
		f.replyJSON(w, map[string]any{"ok": true, "result": true})
	}
}

func (f *fakeBot) replyJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	b, _ := json.Marshal(v)
	_, _ = w.Write(b)
}

func (f *fakeBot) pushMessage(chatID int64, text string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.updates = append(f.updates, tgUpdate{
		UpdateID: f.nextID,
		Message:  &tgMessage{MessageID: f.nextID * 10, Chat: tgChatRef{ID: chatID}, Text: text},
	})
}

func (f *fakeBot) pushCallback(chatID int64, data string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.nextID++
	f.updates = append(f.updates, tgUpdate{
		UpdateID: f.nextID,
		CallbackQuery: &tgCallback{ID: "cb" + strconv.FormatInt(f.nextID, 10), Data: data,
			Message: &tgMessage{MessageID: 555, Chat: tgChatRef{ID: chatID}}},
	})
}

// mockAsker returns a fixed reply and records the turns.
type mockAsker struct {
	mu    sync.Mutex
	turns []string
	reply string
}

func (m *mockAsker) Ask(ctx context.Context, message string, history []ai.Message) (ai.AskReply, error) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.turns = append(m.turns, message)
	return ai.AskReply{Reply: m.reply}, nil
}

// fakeApprover stands in for api.Server.ApproveAIAction.
type fakeApprover struct {
	mu     sync.Mutex
	called []int64
	status string
	output string
	err    error
}

func (f *fakeApprover) ApproveAIAction(ctx context.Context, id int64, via string) (string, string, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.called = append(f.called, id)
	return f.status, f.output, f.err
}

// newPollerTest builds a poller wired to the fake bot + a tempdir store.
func newPollerTest(t *testing.T) (*poller, *fakeBot, *store.Store) {
	t.Helper()
	fb := &fakeBot{}
	srv := httptest.NewServer(http.HandlerFunc(fb.handler))
	t.Cleanup(srv.Close)

	st, err := store.Open(t.TempDir()+"/tg.sqlite", nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })

	p := &poller{
		api:      newBotAPI("111:TEST", srv.URL),
		allowed:  map[string]bool{"42": true},
		st:       st,
		agent:    &mockAsker{reply: "ok"},
		approver: &fakeApprover{},
	}
	return p, fb, st
}

func TestPoller_ChatTurn_ReplySent(t *testing.T) {
	p, fb, st := newPollerTest(t)
	p.agent = &mockAsker{reply: "сервер web1 работает"}
	p.dispatch(context.Background(), tgUpdate{Message: &tgMessage{Chat: tgChatRef{ID: 42}, Text: "что с web1?"}})

	if len(fb.sent) != 1 || !strings.Contains(fb.sent[0], "сервер web1 работает") {
		t.Fatalf("want agent reply in sendMessage, got %v", fb.sent)
	}
	// Turn persisted to the SHARED server-side history (user+assistant) — the web chat will
	// render the same messages from /api/ai/history.
	msgs, err := st.ListChatMessages(context.Background(), 50)
	if err != nil || len(msgs) != 2 {
		t.Fatalf("shared history want 2 rows, got %d (err=%v)", len(msgs), err)
	}
	if msgs[0].Role != "user" || msgs[0].Content != "что с web1?" || msgs[1].Role != "assistant" {
		t.Fatalf("history mismatch: %+v", msgs)
	}
	t.Logf("[IMP:8][TestPoller_ChatTurn][RESULT] sent=%d shared_history=%d", len(fb.sent), len(msgs))
}

func TestPoller_LongReplySplit(t *testing.T) {
	p, fb, _ := newPollerTest(t)
	long := strings.Repeat("line\n", 1200) // ~6000 chars -> 2 chunks
	p.agent = &mockAsker{reply: long}
	p.dispatch(context.Background(), tgUpdate{Message: &tgMessage{Chat: tgChatRef{ID: 42}, Text: "report"}})
	if len(fb.sent) != 2 {
		t.Fatalf("want 2 chunks, got %d", len(fb.sent))
	}
	for i, s := range fb.sent {
		if len(s) > 4100 {
			t.Fatalf("chunk %d too big: %d", i, len(s))
		}
	}
	t.Logf("[IMP:8][TestPoller_LongReply][RESULT] chunks=%d sizes=%d,%d", len(fb.sent), len(fb.sent[0]), len(fb.sent[1]))
}

func TestPoller_AllowlistDenied_AuditWritten(t *testing.T) {
	p, fb, st := newPollerTest(t)
	p.dispatch(context.Background(), tgUpdate{Message: &tgMessage{Chat: tgChatRef{ID: 999}, Text: "hello"}})
	if len(fb.sent) != 0 {
		t.Fatalf("foreign chat must not be answered, sent=%v", fb.sent)
	}
	var n int
	_ = st.DB.QueryRow(`SELECT COUNT(*) FROM audit_log WHERE action='tg_chat_denied'`).Scan(&n)
	if n != 1 {
		t.Fatalf("want 1 deny audit row, got %d", n)
	}
	// No history recorded for foreign chat (shared store stays empty).
	msgs, _ := st.ListChatMessages(context.Background(), 50)
	if len(msgs) != 0 {
		t.Fatalf("foreign chat must not enter shared history, got %d rows", len(msgs))
	}
	t.Logf("[IMP:9][TestPoller_Allowlist][DENIED] audit=1 sent=0")
}

func TestPoller_AnnouncesPendingWithButtons(t *testing.T) {
	p, fb, st := newPollerTest(t)
	ctx := context.Background()
	vmID, _ := st.CreateVM(ctx, store.VM{Name: "web1", Hostname: "h", PortSSH: 22})
	preID, _ := st.CreateAIAction(ctx, store.AIAction{VMID: vmID, Command: "old", Reason: "pre-turn"})
	// The mock agent PROPOSES a new action mid-turn (simulating propose_command).
	p.agent = &askerThatProposes{st: st, vmID: vmID, reply: "предложил команду"}
	p.dispatch(ctx, tgUpdate{Message: &tgMessage{Chat: tgChatRef{ID: 42}, Text: "перезапусти nginx"}})

	// agent reply + ONE announcement (only the new action, not preID): the announce text carries
	// "action #N" + the command, and its message carries the a:<id>:ok/no buttons in reply_markup.
	var announcements int
	for i, s := range fb.sent {
		if strings.Contains(s, "action #") {
			announcements++
			if !strings.Contains(s, "systemctl restart nginx") {
				t.Fatalf("announce missing command: %s", s)
			}
			if i >= len(fb.markups) || !strings.Contains(fb.markups[i], "a%3A") && !strings.Contains(fb.markups[i], "a:") {
				t.Fatalf("announce missing approve buttons: %v", fb.markups)
			}
		}
	}
	if announcements != 1 {
		t.Fatalf("want exactly 1 announcement, got %d (sent=%v)", announcements, fb.sent)
	}
	_ = preID
	t.Logf("[IMP:8][TestPoller_Announce][RESULT] sent=%d announcements=%d", len(fb.sent), announcements)
}

// askerThatProposes creates a pending action DURING the turn (as propose_command would).
type askerThatProposes struct {
	st    *store.Store
	vmID  int64
	reply string
}

func (a *askerThatProposes) Ask(ctx context.Context, message string, history []ai.Message) (ai.AskReply, error) {
	_, err := a.st.CreateAIAction(ctx, store.AIAction{VMID: a.vmID, Command: "systemctl restart nginx", Reason: "restart", RequestedBy: "ai"})
	if err != nil {
		return ai.AskReply{}, err
	}
	return ai.AskReply{Reply: a.reply}, nil
}

func TestPoller_CallbackApprove_RunsApprover(t *testing.T) {
	p, fb, st := newPollerTest(t)
	ctx := context.Background()
	vmID, _ := st.CreateVM(ctx, store.VM{Name: "web1", Hostname: "h", PortSSH: 22})
	actID, _ := st.CreateAIAction(ctx, store.AIAction{VMID: vmID, Command: "uptime"})
	fa := &fakeApprover{status: "done", output: "up 5 days"}
	p.approver = fa

	p.dispatch(ctx, tgUpdate{CallbackQuery: &tgCallback{ID: "cb1", Data: "a:" + strconv.FormatInt(actID, 10) + ":ok",
		Message: &tgMessage{MessageID: 555, Chat: tgChatRef{ID: 42}}}})

	if len(fa.called) != 1 || fa.called[0] != actID {
		t.Fatalf("approver not called once with %d: %v", actID, fa.called)
	}
	if len(fb.edits) != 1 || !strings.Contains(fb.edits[0], "up 5 days") {
		t.Fatalf("message not edited with output: %v", fb.edits)
	}
	if len(fb.answers) == 0 {
		t.Fatalf("callback not acknowledged")
	}
	t.Logf("[IMP:9][TestPoller_CallbackApprove][RESULT] approver=%d edit=ok answers=%d", actID, len(fb.answers))
}

func TestPoller_CallbackReject_AndNotPending(t *testing.T) {
	p, fb, st := newPollerTest(t)
	ctx := context.Background()
	vmID, _ := st.CreateVM(ctx, store.VM{Name: "web1", Hostname: "h", PortSSH: 22})
	actID, _ := st.CreateAIAction(ctx, store.AIAction{VMID: vmID, Command: "uptime"})
	fa := &fakeApprover{status: "done"}
	p.approver = fa

	// Reject via button.
	p.dispatch(ctx, tgUpdate{CallbackQuery: &tgCallback{ID: "cb1", Data: "a:" + strconv.FormatInt(actID, 10) + ":no",
		Message: &tgMessage{MessageID: 555, Chat: tgChatRef{ID: 42}}}})
	got, _ := st.GetAIAction(ctx, actID)
	if got.Status != "rejected" {
		t.Fatalf("want rejected, got %s", got.Status)
	}
	if len(fa.called) != 0 {
		t.Fatalf("reject must not execute, approver called %v", fa.called)
	}

	// Same button again -> graceful "already handled", no approver call, edit attempted.
	before := len(fb.edits)
	p.dispatch(ctx, tgUpdate{CallbackQuery: &tgCallback{ID: "cb2", Data: "a:" + strconv.FormatInt(actID, 10) + ":no",
		Message: &tgMessage{MessageID: 555, Chat: tgChatRef{ID: 42}}}})
	if len(fa.called) != 0 {
		t.Fatalf("second press must not execute")
	}
	if len(fb.answers) < 2 || !strings.Contains(strings.Join(fb.answers, " "), "already handled") {
		t.Fatalf("want already-handled acknowledgement, got %v", fb.answers)
	}
	t.Logf("[IMP:8][TestPoller_CallbackReject][RESULT] status=rejected edits=%d answers=%d", len(fb.edits)-before, len(fb.answers))
}

func TestPoller_ForeignCallbackIgnored(t *testing.T) {
	p, _, st := newPollerTest(t)
	ctx := context.Background()
	vmID, _ := st.CreateVM(ctx, store.VM{Name: "v", Hostname: "h", PortSSH: 22})
	actID, _ := st.CreateAIAction(ctx, store.AIAction{VMID: vmID, Command: "uptime"})
	fa := &fakeApprover{status: "done"}
	p.approver = fa

	p.dispatch(ctx, tgUpdate{CallbackQuery: &tgCallback{ID: "cb1", Data: "a:" + strconv.FormatInt(actID, 10) + ":ok",
		Message: &tgMessage{MessageID: 555, Chat: tgChatRef{ID: 666}}}})
	if len(fa.called) != 0 {
		t.Fatalf("foreign chat callback must not execute, called=%v", fa.called)
	}
	t.Logf("[IMP:9][TestPoller_ForeignCallback][DENIED] approver=0")
}

func TestPoller_SkipBacklog_ConfirmsPast(t *testing.T) {
	fb := &fakeBot{}
	srv := httptest.NewServer(http.HandlerFunc(fb.handler))
	t.Cleanup(srv.Close)
	st, err := store.Open(t.TempDir()+"/tg2.sqlite", nil)
	if err != nil {
		t.Fatalf("store.Open: %v", err)
	}
	t.Cleanup(func() { _ = st.Close() })
	p := &poller{api: newBotAPI("111:TEST", srv.URL), allowed: map[string]bool{"42": true},
		st: st, agent: &mockAsker{reply: "x"}, approver: &fakeApprover{}}

	// Queue two stale updates + one fresh; after restart only the fresh must be handled.
	fb.pushMessage(42, "old command 1")
	fb.pushMessage(42, "old command 2")
	fb.pushMessage(42, "new message")

	offset := p.skipBacklog(context.Background())
	if offset != 4 { // updates 1..3 queued -> nextID==3, skipBacklog returns 3+1
		t.Fatalf("want offset 4, got %d", offset)
	}
	p.dispatch(context.Background(), tgUpdate{UpdateID: 3, Message: &tgMessage{Chat: tgChatRef{ID: 42}, Text: "new message"}})
	if len(fb.sent) != 1 {
		t.Fatalf("only the fresh turn should produce a reply, sent=%d", len(fb.sent))
	}
	t.Logf("[IMP:8][TestPoller_SkipBacklog][RESULT] offset=%d sent=%d", offset, len(fb.sent))
}

func TestBotAPI_ConflictDetected(t *testing.T) {
	fb := &fakeBot{conflict: true}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { fb.handler(w, r) }))
	t.Cleanup(srv.Close)
	b := newBotAPI("111:TEST", srv.URL)
	_, err := b.getUpdates(context.Background(), 0, 0)
	if !IsBotConflict(err) {
		t.Fatalf("want conflict error, got %v", err)
	}
	t.Logf("[IMP:8][TestBotAPI][CONFLICT] detected: %v", err)
}

func TestBotAPI_TokenRedacted(t *testing.T) {
	// Server that hangs -> client timeout -> transport error embeds the URL (token).
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(3 * time.Second)
	}))
	t.Cleanup(srv.Close)
	b := newBotAPI("123456:SECRET_TOKEN", srv.URL)
	b.client.Timeout = 200 * time.Millisecond
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	_, err := b.getUpdates(ctx, 0, 0)
	if err == nil {
		t.Fatal("want error")
	}
	if strings.Contains(err.Error(), "SECRET_TOKEN") {
		t.Fatalf("token leaked: %v", err)
	}
	if !strings.Contains(err.Error(), "bot***") {
		t.Fatalf("want redacted marker: %v", err)
	}
	t.Logf("[IMP:9][TestBotAPI][REDACT] %v", err)
}
