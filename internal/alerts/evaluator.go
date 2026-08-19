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
	"sort"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/skibine/vmp/internal/audit"
	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
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
	muted, _ := e.store.MutedVMIDs(e.ctx)
	// Batch-load all edge-trigger state once per cycle (one query) instead of one GetAlertState per
	// (rule,check) pair — the hot loop then reads from this map.
	stateMap, _ := e.store.ListAlertState(e.ctx)
	for _, rule := range rules {
		if !rule.Enabled {
			continue
		}
		for _, res := range latest {
			// Scope: a rule with vm_id matches ONLY that VM's checks; nil = all VMs.
			if rule.VMID != nil && (res.VMID == nil || *rule.VMID != *res.VMID) {
				continue
			}
			// Fleet-wide rules skip muted VMs ("all except this one"). Scoped rules always fire.
			if rule.VMID == nil && res.VMID != nil && muted[*res.VMID] {
				continue
			}
			if rule.CheckType != "" && rule.CheckType != res.CheckType {
				continue
			}
			prev := stateMap[store.AlertStateKey(rule.ID, res.CheckID)]
			// DOWN: entering the trigger status, or still in it past the cooldown (periodic reminder).
			if res.Status == rule.TriggerStatus {
				entering := prev != rule.TriggerStatus
				if entering || !e.inCooldown(rule.ID, res.CheckID, rule.CooldownSec) {
					e.fire(rule, res)
					fired++
				}
				_ = e.store.SetAlertState(e.ctx, rule.ID, res.CheckID, rule.TriggerStatus)
				continue
			}
			// RECOVERED: a critical-trigger rule whose check returns ok after being critical.
			if rule.TriggerStatus == "critical" && res.Status == "ok" && prev == "critical" {
				e.fire(rule, res)
				fired++
				_ = e.store.SetAlertState(e.ctx, rule.ID, res.CheckID, "ok")
			}
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
// @purpose Deliver to the firing SERVER's own channels (per-server routing), record delivery_log,
// @purpose persist the alert. note is "down"/"recovered" shown in the title.
// @complexity 5
// endregion FUNC_fire
func (e *Evaluator) fire(rule store.AlertRule, res store.LatestCheckResult) {
	// WHERE the alert goes is the server's own channels (per-server routing), not the rule's.
	var channels []store.Channel
	if res.VMID != nil {
		channels, _ = e.store.ListVMChannels(e.ctx, *res.VMID)
	}
	// Localize the message to the operator's UI locale; use the server name as the subject.
	locale, _ := e.store.GetSetting(e.ctx, "ui_locale")
	host := rule.Name
	if res.VMID != nil {
		if vm, err := e.store.GetVM(e.ctx, *res.VMID); err == nil && vm.Name != "" {
			host = vm.Name
		}
	}
	// Rule name fallback: older/programmatically-created rules may have an empty name, which would
	// render the alert footer as "(rule= check=...)". Fall back to a readable label.
	ruleName := strings.TrimSpace(rule.Name)
	if ruleName == "" {
		ruleName = "server down"
	}
	title, body := alertText(locale, res.Status, res.CheckType, res.LatencyMS, host)
	msg := Message{
		Severity: rule.Severity, RuleName: ruleName,
		CheckID: res.CheckID, CheckType: res.CheckType, VMID: res.VMID,
		Title: title, Body: body,
	}
	deliveryLog := map[string]any{}
	// in-app delivery = a bell NOTIFICATION, but ONLY when the operator attached the in-app
	// channel to this server (explicit opt-in, same as telegram). The full fired-alert journal
	// lives on the events page (alert_fire rows) — the bell is a DELIVERY target, not the journal.
	inApp := false
	for _, ch := range channels {
		if !ch.Enabled {
			continue
		}
		if ch.Type == "in-app" {
			inApp = true
			continue // delivered below (needs store access), not via the registry
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
	if inApp {
		if _, nerr := e.store.CreateNotification(e.ctx, store.Notification{
			Title: msg.Title, Body: msg.Body, Kind: "alert", RefID: res.VMID,
		}); nerr != nil {
			logging.LDD(e.logger, 8, "fire", "NOTIF_FAIL", nerr.Error())
		}
	}
	alertID, err := e.store.InsertAlert(e.ctx, store.Alert{
		RuleID: rule.ID, CheckID: res.CheckID, VMID: res.VMID,
		Severity: rule.Severity, Message: msg.Title + " — " + msg.Body, DeliveryLog: deliveryLog,
	})
	if err != nil {
		logging.LDD(e.logger, 10, "fire", "INSERT_FAIL", err.Error())
		return
	}
	// The fired alert is ALSO an event in the tamper-evident journal (category "alert") — the
	// events page is the single place where the operator reviews what happened (alerts included).
	// `delivered=` summarizes WHERE the alert actually went (per-channel ok/err) so a silent
	// telegram is diagnosable straight from the event row (detached channels => "none").
	vmPart := ""
	if res.VMID != nil {
		vmPart = fmt.Sprintf("vm=%d ", *res.VMID)
	}
	delivered := make([]string, 0, len(deliveryLog))
	for _, v := range deliveryLog {
		if entry, ok := v.(map[string]any); ok {
			kind, _ := entry["type"].(string)
			if entry["ok"] == true {
				delivered = append(delivered, kind+":ok")
			} else if errText, _ := entry["err"].(string); errText != "" {
				delivered = append(delivered, kind+":"+truncateRunes(errText, 60))
			}
		}
	}
	sort.Strings(delivered)
	if len(delivered) == 0 {
		delivered = append(delivered, "none (no channels attached)")
	}
	_ = audit.Append(e.store.DB, e.logger, audit.Entry{
		Plane: audit.PlaneA, Action: "alert_fire", Success: true,
		Detail: fmt.Sprintf("%srule=%s check=%d severity=%s delivered=%s msg=%s",
			vmPart, ruleName, res.CheckID, rule.Severity,
			strings.Join(delivered, ", "), truncateRunes(msg.Title, 120)),
	})
	logging.LDD(e.logger, 9, "fire", "FIRED",
		fmt.Sprintf("alert=%d rule=%s check=%d severity=%s", alertID, rule.Name, res.CheckID, rule.Severity))
}

// truncateRunes clips s to at most n runes (event detail stays one readable line).
func truncateRunes(s string, n int) string {
	if utf8.RuneCountInString(s) <= n {
		return s
	}
	r := []rune(s)
	return string(r[:n]) + "…"
}

// parseTime parses the SQLite-produced RFC3339-ish timestamp.
func parseTime(s string) (time.Time, error) {
	return time.Parse(time.RFC3339Nano, s)
}
