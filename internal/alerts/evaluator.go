// Package alerts — evaluator: consumes latest results, fires alerts with cooldown.
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(8): Evaluator; TECH(8): goroutines]
// @purpose Periodically evaluate enabled alert rules against the latest check results and
//
//	fire (with cooldown) delivering to attached channels. Plane A: no credential vault.
//
// @io New(store, registry, logger, tickEvery) -> *Evaluator ; Start(ctx) ; Stop()
// @invariants
//   - A rule fires at most once per (rule,check) within its cooldown window.
//   - Cooldown is persisted (via LastAlertFor), so a restart does not double-fire.
//   - Delivery failures are recorded per-channel in delivery_log; they do not abort the alert.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: evaluator, alert, tick, evaluate, cooldown, fire, deliver, Plane A
// STRUCTURE: ▶ Start → ○ loop(tick→evaluate) → 〈rule×result match? cooldown?〉 → ⊕ fire → ⎋ Stop
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
	"github.com/skibine/vm-pulse/internal/store"
)

// region STRUCT_Evaluator [DOMAIN(8): Alerting; CONCEPT(7): Orchestrator; TECH(7): goroutines]
// @purpose Own the alert evaluation loop.
// endregion STRUCT_Evaluator
type Evaluator struct {
	store     *store.Store
	reg       *Registry
	logger    *slog.Logger
	tickEvery time.Duration

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	startMu sync.Mutex
	started bool
}

// region FUNC_New [DOMAIN(7): Alerting; CONCEPT(6): Build; TECH(4): struct]
// @purpose Construct an Evaluator; clamps tickEvery to >=1s.
// @complexity 2
// endregion FUNC_New
func New(s *store.Store, reg *Registry, logger *slog.Logger, tickEvery time.Duration) *Evaluator {
	if tickEvery < time.Second {
		tickEvery = time.Second
	}
	return &Evaluator{store: s, reg: reg, logger: logger, tickEvery: tickEvery}
}

// region FUNC_Start [DOMAIN(7): Alerting; CONCEPT(7): Lifecycle; TECH(7): goroutines]
// @purpose Launch the evaluation loop under the parent context.
// @complexity 3
// endregion FUNC_Start
func (e *Evaluator) Start(parent context.Context) {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.started {
		return
	}
	e.ctx, e.cancel = context.WithCancel(parent)
	e.started = true
	e.wg.Add(1)
	go e.loop()
	logging.LDD(e.logger, 9, "Start", "STARTED", fmt.Sprintf("tick=%s", e.tickEvery))
}

// region FUNC_Stop [DOMAIN(7): Alerting; CONCEPT(7): Lifecycle; TECH(7): goroutines]
// @purpose Cancel the loop and wait for it to exit.
// @complexity 2
// endregion FUNC_Stop
func (e *Evaluator) Stop() {
	e.startMu.Lock()
	if !e.started {
		e.startMu.Unlock()
		return
	}
	e.started = false
	e.startMu.Unlock()
	e.cancel()
	e.wg.Wait()
	logging.LDD(e.logger, 9, "Stop", "STOPPED", "evaluator drained")
}

func (e *Evaluator) loop() {
	defer e.wg.Done()
	ticker := time.NewTicker(e.tickEvery)
	defer ticker.Stop()
	e.evaluate()
	for {
		select {
		case <-ticker.C:
			e.evaluate()
		case <-e.ctx.Done():
			return
		}
	}
}

// region FUNC_evaluate [DOMAIN(8): Alerting; CONCEPT(8): Evaluate; TECH(7): match+cooldown]
// @purpose One evaluation pass: match rules against latest results, enforce cooldown, fire.
// @complexity 7
// endregion FUNC_evaluate
func (e *Evaluator) evaluate() {
	rules, err := e.store.ListAlertRules(e.ctx)
	if err != nil {
		logging.LDD(e.logger, 10, "evaluate", "LIST_RULES_FAIL", err.Error())
		return
	}
	latest, err := e.store.LatestCheckResults(e.ctx)
	if err != nil {
		logging.LDD(e.logger, 10, "evaluate", "LIST_RESULTS_FAIL", err.Error())
		return
	}
	fired := 0
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		channels, _ := e.store.ListChannelsForRule(e.ctx, rule.ID)
		for _, res := range latest {
			if rule.CheckType != "" && rule.CheckType != res.CheckType {
				continue
			}
			if res.Status != rule.TriggerStatus {
				continue
			}
			if e.inCooldown(rule.ID, res.CheckID, rule.CooldownSec) {
				continue
			}
			e.fire(rule, res, channels)
			fired++
		}
	}
	if fired > 0 {
		logging.LDD(e.logger, 9, "evaluate", "FIRED", fmt.Sprintf("%d alerts", fired))
	}
}

// inCooldown reports whether (ruleID,checkID) fired within cooldownSec.
func (e *Evaluator) inCooldown(ruleID, checkID int64, cooldownSec int) bool {
	if cooldownSec <= 0 {
		return false
	}
	ts, ok, err := e.store.LastAlertFor(e.ctx, ruleID, checkID)
	if err != nil || !ok {
		return false
	}
	last, perr := parseTime(ts)
	if perr != nil {
		return false
	}
	return time.Since(last) < time.Duration(cooldownSec)*time.Second
}

// region FUNC_fire [DOMAIN(8): Alerting; CONCEPT(7): Fire; TECH(6): deliver+persist]
// @purpose Deliver to all attached channels, record delivery_log, persist the alert.
// @complexity 5
// endregion FUNC_fire
func (e *Evaluator) fire(rule store.AlertRule, res store.LatestCheckResult, channels []store.Channel) {
	msg := Message{
		Severity: rule.Severity, RuleName: rule.Name,
		CheckID: res.CheckID, CheckType: res.CheckType, VMID: res.VMID,
		Title: fmt.Sprintf("check %s is %s", res.CheckType, res.Status),
		Body:  fmt.Sprintf("status=%s latency_ms=%.1f", res.Status, res.LatencyMS),
	}
	deliveryLog := map[string]any{}
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		impl, ok := e.reg.Get(ch.Type)
		entry := map[string]any{"channel": ch.Name, "type": ch.Type}
		if !ok {
			entry["ok"] = false
			entry["err"] = "no implementation for type: " + ch.Type
		} else if err := impl.Deliver(e.ctx, ch.Config, msg); err != nil {
			entry["ok"] = false
			entry["err"] = err.Error()
			logging.LDD(e.logger, 10, "fire", "DELIVER_FAIL", fmt.Sprintf("channel=%d: %s", ch.ID, err.Error()))
		} else {
			entry["ok"] = true
		}
		deliveryLog[fmt.Sprintf("%d", ch.ID)] = entry
	}
	alertID, err := e.store.InsertAlert(e.ctx, store.Alert{
		RuleID: rule.ID, CheckID: res.CheckID, VMID: res.VMID,
		Severity: rule.Severity, Message: msg.Title + " — " + msg.Body, DeliveryLog: deliveryLog,
	})
	if err != nil {
		logging.LDD(e.logger, 10, "fire", "INSERT_FAIL", err.Error())
		return
	}
	logging.LDD(e.logger, 9, "fire", "FIRED",
		fmt.Sprintf("alert=%d rule=%s check=%d severity=%s", alertID, rule.Name, res.CheckID, rule.Severity))
}

// parseTime parses the SQLite-produced RFC3339-ish timestamp.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
