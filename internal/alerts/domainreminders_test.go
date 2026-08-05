// region FUNC_test_DomainEvaluator_DeletesOneShotAfterChannel [DOMAIN(7): Testing; CONCEPT(8): Execute; TECH(7): evaluator]
// @purpose A one-shot reminder delivered to an external channel is "executed": the row is deleted
// @purpose after a successful send. A repeating reminder (no channel) is kept and only notified.
// @complexity 4
// endregion FUNC_test_DomainEvaluator_DeletesOneShotAfterChannel
package alerts

import (
	"bytes"
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"testing"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

func TestDomainEvaluator_DeletesOneShotAfterChannel(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "drem.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()

	domID, err := s.CreateDomain(ctx, store.Domain{Name: "ex.com"})
	if err != nil {
		t.Fatalf("CreateDomain: %v", err)
	}
	cid, err := s.CreateChannel(ctx, store.Channel{Type: "capture", Name: "cap", Enabled: true})
	if err != nil {
		t.Fatalf("CreateChannel: %v", err)
	}
	// One-shot cert reminder attached to the capture channel; a repeating cert reminder (no channel).
	oneShotID, _ := s.CreateDomainReminder(ctx, store.DomainReminder{DomainID: domID, Kind: "cert", Days: 30, RepeatDays: 0, ChannelID: int(cid)})
	repeatID, _ := s.CreateDomainReminder(ctx, store.DomainReminder{DomainID: domID, Kind: "cert", Days: 14, RepeatDays: 7})

	cap := &captureChannel{}
	reg := NewRegistry(cap)
	probe := func(_ context.Context, domain string) (DomainProbe, error) {
		return DomainProbe{CertDays: 5, HasCert: true, HasOwner: false}, nil
	}
	ev := NewDomainEvaluator(s, reg, probe, logger, time.Minute)
	ev.ctx = context.Background()
	ev.evaluate()

	exists := func(id int64) bool {
		rems, err := s.ListDomainReminders(ctx, domID)
		if err != nil {
			t.Fatalf("ListDomainReminders: %v", err)
		}
		for _, r := range rems {
			if r.ID == id {
				return true
			}
		}
		return false
	}

	if exists(oneShotID) {
		t.Errorf("one-shot reminder should be deleted after successful channel delivery")
	}
	if !exists(repeatID) {
		t.Errorf("repeating reminder should remain")
	}
	if cap.count() != 1 {
		t.Errorf("want exactly 1 channel delivery (one-shot), got %d", cap.count())
	}
	t.Logf("[IMP:8][TestDomainEval][RESULT] oneShotDeleted=%v repeatKept=%v channelMsgs=%d", !exists(oneShotID), exists(repeatID), cap.count())
}

// failingChannel always fails delivery — used to verify a one-shot reminder is NOT consumed when the
// external push fails, so the evaluator retries it on the next tick instead of dropping the alert.
type failingChannel struct{ n int }

func (*failingChannel) Type() string                       { return "fail" }
func (f *failingChannel) Deliver(context.Context, map[string]any, Message) error { f.n++; return fmt.Errorf("boom") }

// region FUNC_test_DomainEvaluator_OneShotRetriesOnChannelFail [DOMAIN(7): Testing; CONCEPT(8): Retry; TECH(7): evaluator]
// @purpose A one-shot reminder whose external channel delivery fails must survive (not be deleted,
// @purpose not marked notified) so it is retried — the configured Telegram/webhook push is not lost.
// @complexity 3
// endregion FUNC_test_DomainEvaluator_OneShotRetriesOnChannelFail
func TestDomainEvaluator_OneShotRetriesOnChannelFail(t *testing.T) {
	var buf bytes.Buffer
	logger := logging.Setup(slog.LevelDebug, &buf)
	s, err := store.Open(filepath.Join(t.TempDir(), "drem2.sqlite"), logger)
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() { _ = s.Close() })
	ctx := context.Background()
	domID, _ := s.CreateDomain(ctx, store.Domain{Name: "ex.com"})
	cid, _ := s.CreateChannel(ctx, store.Channel{Type: "fail", Name: "f", Enabled: true})
	fc := &failingChannel{}
	reg := NewRegistry(fc)
	oneShotID, _ := s.CreateDomainReminder(ctx, store.DomainReminder{DomainID: domID, Kind: "cert", Days: 30, RepeatDays: 0, ChannelID: int(cid)})
	probe := func(_ context.Context, domain string) (DomainProbe, error) {
		return DomainProbe{CertDays: 5, HasCert: true}, nil
	}
	ev := NewDomainEvaluator(s, reg, probe, logger, time.Minute)
	ev.ctx = context.Background()
	ev.evaluate() // first pass: channel fails -> reminder must survive, not notified
	ev.evaluate() // second pass: must retry (deliver attempted again)

	rems, _ := s.ListDomainReminders(ctx, domID)
	var stillExists bool
	var lastNotif string
	for _, r := range rems {
		if r.ID == oneShotID {
			stillExists = true
			lastNotif = r.LastNotified
		}
	}
	if !stillExists {
		t.Fatal("one-shot reminder must survive a failed external delivery (retry expected)")
	}
	if lastNotified := lastNotif; lastNotified != "" {
		t.Fatalf("one-shot must NOT be marked notified on channel failure, got last_notified=%q", lastNotified)
	}
	if fc.n != 2 {
		t.Fatalf("expected 2 delivery attempts (retry), got %d", fc.n)
	}
	t.Logf("[IMP:9][TestOneShotRetry][RESULT] survived=%v lastNotified=%q attempts=%d", stillExists, lastNotif, fc.n)
}
