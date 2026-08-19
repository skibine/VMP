// Package alerts — domain reminder evaluator (list-based, with repeat).
//
// region MODULE_CONTRACT [DOMAIN(8): Alerting; CONCEPT(8]: DomainReminders; TECH(7]: goroutines]
// @purpose Periodically evaluate every domain_reminders row and deliver notifications:
//
//	(1) cert/owner: fire when the probed remaining days cross the reminder threshold; if repeat_days>0
//	    re-fire every repeat_days while still triggered, else fire once on entry into the window.
//	(2) dns: fire when the DNS signature changes vs the baseline (first probe = silent baseline).
//	Delivery is ALWAYS in-app (stored notification -> bell center + toast); PLUS the attached
//	external channel (telegram/webhook) when channel_id > 0. The probe is injected (no monitor cycle).
//
// @io NewDomainEvaluator(store, registry, probe, logger, tickEvery) -> *DomainEvaluator
// @invariants
//   - One-shot reminders (repeat_days=0) fire at most once per entry into the window.
//   - Repeating reminders re-fire no sooner than repeat_days after the last notification.
//   - DNS first probe per domain is a silent baseline; only subsequent signature changes alert.
//   - certDays/ownerDays < 0 (unparseable) never fires the expiry reminder.
//   - Delivery failures are logged; they never abort the loop.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: domain, reminder, list, cert, owner, dns change, repeat, signature, in-app
// STRUCTURE: ▶ Start → ○ loop(tick→evaluate) → ┌reminders┐ → ◇ probe(per domain) → 〈triggered? dedup?〉 → ⊕ deliver → ⎋
package alerts

import (
	"context"
	"fmt"
	"log/slog"
	"sync"
	"time"

	"github.com/skibine/vmp/internal/logging"
	"github.com/skibine/vmp/internal/store"
)

// DomainProbe is the per-domain probe result the evaluator needs (filled by main.go from
// monitor.ProbeDomain to avoid an import cycle).
type DomainProbe struct {
	CertDays  int
	OwnerDays int
	DNSSig    string // stable hash of the DNS record set
	HasCert   bool
	HasOwner  bool
}

// DomainExpiryFunc probes one domain and returns the values the evaluator compares against.
type DomainExpiryFunc func(ctx context.Context, domain string) (DomainProbe, error)

// region STRUCT_DomainEvaluator [DOMAIN(8): Alerting; CONCEPT(7): Loop; TECH(7): goroutines]
// @purpose Own the domain reminder evaluation loop.
// endregion STRUCT_DomainEvaluator
type DomainEvaluator struct {
	store     *store.Store
	reg       *Registry
	probe     DomainExpiryFunc
	logger    *slog.Logger
	tickEvery time.Duration

	ctx     context.Context
	cancel  context.CancelFunc
	wg      sync.WaitGroup
	startMu sync.Mutex
	started bool
}

// region FUNC_NewDomainEvaluator [DOMAIN(7): Alerting; CONCEPT(6): Build; TECH(4): struct]
// @purpose Construct a DomainEvaluator; clamps tickEvery >=1m.
// @complexity 2
// endregion FUNC_NewDomainEvaluator
func NewDomainEvaluator(s *store.Store, reg *Registry, probe DomainExpiryFunc, logger *slog.Logger, tickEvery time.Duration) *DomainEvaluator {
	if tickEvery < time.Minute {
		tickEvery = time.Minute
	}
	return &DomainEvaluator{store: s, reg: reg, probe: probe, logger: logger, tickEvery: tickEvery}
}

func (e *DomainEvaluator) Start(parent context.Context) {
	e.startMu.Lock()
	defer e.startMu.Unlock()
	if e.started {
		return
	}
	e.ctx, e.cancel = context.WithCancel(parent)
	e.started = true
	e.wg.Add(1)
	go e.loop()
	logging.LDD(e.logger, 9, "DomainStart", "STARTED", fmt.Sprintf("tick=%s", e.tickEvery))
}

func (e *DomainEvaluator) Stop() {
	e.startMu.Lock()
	if !e.started {
		e.startMu.Unlock()
		return
	}
	e.started = false
	e.startMu.Unlock()
	e.cancel()
	e.wg.Wait()
	logging.LDD(e.logger, 9, "DomainStop", "STOPPED", "domain evaluator drained")
}

func (e *DomainEvaluator) loop() {
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

// region FUNC_DomainEvaluator_evaluate [DOMAIN(8): Alerting; CONCEPT(8]: Evaluate; TECH(7]: probe+dedup]
// @purpose One pass: group reminders by domain, probe each domain once, fire triggered reminders.
// @complexity 8
// endregion FUNC_DomainEvaluator_evaluate
func (e *DomainEvaluator) evaluate() {
	reminders, err := e.store.ListAllReminders(e.ctx)
	if err != nil {
		logging.LDD(e.logger, 10, "DomainEval", "LIST_FAIL", err.Error())
		return
	}
	if len(reminders) == 0 {
		return
	}
	// Group reminders by domain and probe each domain once.
	byDomain := map[int64][]store.DomainReminder{}
	for _, r := range reminders {
		byDomain[r.DomainID] = append(byDomain[r.DomainID], r)
	}
	fired := 0
	for domainID, rems := range byDomain {
		dom, derr := e.store.GetDomain(e.ctx, domainID)
		if derr != nil {
			logging.LDD(e.logger, 9, "DomainEval", "DOMAIN_FAIL", fmt.Sprintf("id=%d: %s", domainID, derr.Error()))
			continue
		}
		p, perr := e.probe(e.ctx, dom.Name)
		if perr != nil {
			logging.LDD(e.logger, 8, "DomainEval", "PROBE_FAIL", dom.Name+": "+perr.Error())
			continue
		}
		// DNS change detection: READ-ONLY. The baseline (domains.dns_last_signature) is owned by
		// computeDomainHealth (lazy set on first probe) and the setDnsBaseline ack endpoint. The
		// evaluator must NOT move it — otherwise a real NS/MX/TXT change self-heals (baseline jumps to
		// the new records) before the operator acknowledges it, and the fleet yellow vanishes silently.
		dnsChanged := p.DNSSig != "" && dom.DNSLastSignature != "" && dom.DNSLastSignature != p.DNSSig
		for _, r := range rems {
			switch r.Kind {
			case "cert":
				if p.HasCert && p.CertDays >= 0 && p.CertDays <= r.Days && e.shouldFire(r) {
					if e.deliver(dom, r, p.CertDays) {
						_ = e.store.MarkReminderNotified(e.ctx, r.ID)
					}
					fired++
				}
			case "owner":
				if p.HasOwner && p.OwnerDays >= 0 && p.OwnerDays <= r.Days && e.shouldFire(r) {
					if e.deliver(dom, r, p.OwnerDays) {
						_ = e.store.MarkReminderNotified(e.ctx, r.ID)
					}
					fired++
				}
			case "dns":
				if dnsChanged && e.shouldFire(r) {
					if e.deliver(dom, r, 0) {
						_ = e.store.MarkReminderNotified(e.ctx, r.ID)
					}
					fired++
				}
			}
		}
	}
	if fired > 0 {
		logging.LDD(e.logger, 9, "DomainEval", "FIRED", fmt.Sprintf("%d reminders", fired))
	}
}

// shouldFire applies the per-reminder dedup: one-shot fires only before the first notification;
// repeating fires no sooner than repeat_days after the last notification.
func (e *DomainEvaluator) shouldFire(r store.DomainReminder) bool {
	if r.LastNotified == "" {
		return true
	}
	if r.RepeatDays <= 0 {
		return false // one-shot already fired
	}
	last, err := time.Parse(time.RFC3339Nano, r.LastNotified)
	if err != nil {
		return true
	}
	return time.Since(last) >= time.Duration(r.RepeatDays)*24*time.Hour
}

// region FUNC_DomainEvaluator_deliver [DOMAIN(8): Alerting; CONCEPT(7]: Deliver; TECH(6]: channels]
// @purpose Always create an in-app notification; additionally push to the attached channel.
// @complexity 5
// endregion FUNC_DomainEvaluator_deliver
// deliver sends a reminder: an in-app notification (on first fire only, to avoid duplicates across
// retries) plus an optional external channel push. Returns ok=true when there is no external channel
// OR the external push succeeded — only then may the caller mark the reminder notified. A failed
// external push returns ok=false so the reminder is retried on the next tick (a one-shot keeps its
// external delivery instead of being silently dropped).
func (e *DomainEvaluator) deliver(d store.Domain, r store.DomainReminder, days int) (ok bool) {
	var title, body string
	switch r.Kind {
	case "cert":
		title = fmt.Sprintf("%s: certificate expires in %d days", d.Name, days)
		body = fmt.Sprintf("rotate/renew the TLS certificate (%dd left)", days)
	case "owner":
		title = fmt.Sprintf("%s: registration expires in %d days", d.Name, days)
		body = fmt.Sprintf("renew the domain registration (%dd left)", days)
	default:
		title = fmt.Sprintf("%s: DNS records changed", d.Name)
		body = "NS / MX / TXT records differ from the previous probe"
	}
	// In-app notification only on the FIRST fire (LastNotified empty) — otherwise a repeating
	// reminder or a retried one-shot would spam duplicate notifications every tick.
	if r.LastNotified == "" {
		refID := r.ID
		if _, err := e.store.CreateNotification(e.ctx, store.Notification{Title: title, Body: body, Kind: "reminder", RefID: &refID}); err != nil {
			logging.LDD(e.logger, 9, "DomainDeliver", "NOTIF_FAIL", err.Error())
		}
	}
	if r.ChannelID <= 0 {
		return true // no external channel — in-app notification is the durable delivery
	}
	ch, err := e.store.GetChannel(e.ctx, int64(r.ChannelID))
	if err != nil || !ch.Enabled {
		return false // channel missing/disabled — retry later when it is available
	}
	impl, found := e.reg.Get(ch.Type)
	if !found {
		return false // unknown channel type (config error) — retry
	}
	msg := Message{Severity: "warning", RuleName: "domain " + r.Kind + " reminder", CheckID: d.ID, CheckType: "domain", Title: title, Body: body}
	if err := impl.Deliver(e.ctx, ch.Config, msg); err != nil {
		logging.LDD(e.logger, 9, "DomainDeliver", "FAIL", fmt.Sprintf("channel=%d %s: %s", ch.ID, ch.Type, err.Error()))
		return false // external delivery failed — do NOT mark notified, retry next tick
	}
	if r.RepeatDays <= 0 {
		// Successfully delivered externally — a one-shot reminder is now executed and will never
		// legitimately fire again, so drop it.
		if derr := e.store.DeleteDomainReminder(e.ctx, r.ID); derr != nil {
			logging.LDD(e.logger, 9, "DomainDeliver", "DEL_FAIL", derr.Error())
		} else {
			logging.LDD(e.logger, 9, "DomainDeliver", "EXECUTED", fmt.Sprintf("domain=%s kind=%s one-shot reminder=%d deleted", d.Name, r.Kind, r.ID))
		}
	}
	logging.LDD(e.logger, 9, "DomainDeliver", "SENT", fmt.Sprintf("domain=%s kind=%s days=%d channel=%d repeat=%d", d.Name, r.Kind, days, ch.ID, r.RepeatDays))
	return true
}
