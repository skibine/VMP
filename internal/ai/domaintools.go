// Package ai — domain tools (Plane A reads): stored fleet view + one live probe.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Observability; CONCEPT(8): DomainTools; TECH(7): store,monitor]
// @purpose Let the assistant answer domain questions ("when does the example.pro certificate
//
//	expire?") two ways: list_domains reads the STORED check results (cheap, no live probes), and
//	get_domain_info runs one live DNS+TLS+whois probe (the same call a domain click makes in the UI).
//
// @invariants
//   - list_domains never performs network I/O — it reports the latest stored check rows only.
//   - get_domain_info resolves the domain by id OR by exact name (case-insensitive).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: list_domains, get_domain_info, domain, cert, expiry, whois, dns, ai tools
// STRUCTURE: ▶ list_domains: ┌store┐ → ○ ListDomains → ⊕ LatestResultsForDomain → ⎷ JSON ; get_domain_info: ┌name|id┐ → ◇ resolve → ⚡ ProbeDomain → ⎷ JSON
package ai

import (
	"context"
	"fmt"
	"strconv"
	"strings"

	"github.com/skibine/vm-pulse/internal/monitor"
	"github.com/skibine/vm-pulse/internal/store"
)

// DomainTools builds the domain tools: reads (list_domains stored + get_domain_info live probe)
// plus config mutators (update_domain, reminders CRUD, DNS ack).
func DomainTools(s *store.Store) []Tool {
	reads := []Tool{
		{
			Name: "list_domains",
			Description: "List ALL monitored domains with id, name, registrar, monitoring toggles " +
				"(dns/whois/tls), notify thresholds, and the LATEST STORED status of each domain check " +
				"(whois/tls/dns). Cheap (no network). Use it to find the domain id first; the stored " +
				"statuses come from the periodic background checks and may be up to a few hours old — " +
				"for the current live picture call get_domain_info.",
			Parameters: map[string]any{"type": "object", "properties": map[string]any{}},
			Run: func(ctx context.Context, _ map[string]any) (string, error) {
				doms, err := s.ListDomains(ctx)
				if err != nil {
					return "", err
				}
				out := make([]map[string]any, 0, len(doms))
				for _, d := range doms {
					entry := map[string]any{
						"id": d.ID, "name": d.Name, "registrar": d.Registrar,
						"monitor_dns": d.MonitorDNS, "monitor_whois": d.MonitorWhois, "monitor_tls": d.MonitorTLS,
						"cert_notify_days": d.CertNotifyDays, "owner_notify_days": d.OwnerNotifyDays,
						"checks":          map[string]any{},
					}
					if rows, err := s.LatestResultsForDomain(ctx, d.ID); err == nil {
						checks := map[string]any{}
						for _, r := range rows {
							checks[r.CheckType] = map[string]any{
								"status": r.LatestStatus, "ts": r.LatestTS, "message": r.LatestMessage,
							}
						}
						entry["checks"] = checks
					}
					out = append(out, entry)
				}
				return jsonStr(out)
			},
		},
		{
			Name: "get_domain_info",
			Description: "Run ONE live probe (DNS + TLS + whois/RDAP) of a monitored domain and return " +
				"the current picture: certificate (issuer, not_after, days_remaining, status), " +
				"registration (registrar, expiry, days_remaining), and DNS records (A/AAAA). " +
				"This directly answers 'when does the certificate / registration expire'. " +
				"Pass the domain id from list_domains, or the exact domain name.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain_id": map[string]any{"type": "integer", "description": "domain id (preferred)"},
					"name":      map[string]any{"type": "string", "description": "exact domain name, e.g. example.pro"},
				},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				var name string
				if id, ok := intArg(args, "domain_id"); ok && id > 0 {
					d, err := s.GetDomain(ctx, id)
					if err != nil {
						return jsonStr(map[string]any{"error": "domain not found", "domain_id": id})
					}
					name = d.Name
				} else if n, ok := args["name"].(string); ok {
					name = strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(n), "www."))
				}
				if name == "" {
					return "", errDomainArgRequired
				}
				info, perr := monitor.ProbeDomain(ctx, name)
				if perr != nil {
					return jsonStr(map[string]any{"error": "probe failed: " + perr.Error(), "domain": name})
				}
				return jsonStr(info)
			},
		},
	}

	mutators := DomainMutatorTools(s)
	return append(reads, mutators...)
}

// DomainMutatorTools builds the domain config tools: update_domain, reminders CRUD, DNS ack.
// Separate constructor so the read-only subset can be tested without network probes.
func DomainMutatorTools(s *store.Store) []Tool {
	resolveDomain := func(ctx context.Context, args map[string]any) (store.Domain, error) {
		if id, ok := intArg(args, "domain_id"); ok && id > 0 {
			return s.GetDomain(ctx, id)
		}
		if name, ok := args["name"].(string); ok && name != "" {
			name = strings.ToLower(strings.TrimSpace(strings.TrimPrefix(strings.TrimSpace(name), "www.")))
			doms, err := s.ListDomains(ctx)
			if err != nil {
				return store.Domain{}, err
			}
			for _, d := range doms {
				if d.Name == name {
					return d, nil
				}
			}
			return store.Domain{}, fmt.Errorf("domain not monitored: %s", name)
		}
		return store.Domain{}, fmt.Errorf("domain_id or name required")
	}
	resolveChannel := func(ctx context.Context, spec string) (int64, error) {
		if spec == "" {
			return 0, nil
		}
		chs, err := s.ListChannels(ctx)
		if err != nil {
			return 0, err
		}
		for _, c := range chs {
			if fmt.Sprintf("%d", c.ID) == spec || strings.EqualFold(c.Name, strings.TrimSpace(spec)) {
				return c.ID, nil
			}
		}
		return 0, fmt.Errorf("unknown channel: %s", spec)
	}

	return []Tool{
		{
			Name: "update_domain",
			Description: "Edit a monitored domain's settings: monitor_dns/monitor_whois/monitor_tls " +
				"(bool), cert_notify_days/owner_notify_days (reminder thresholds), dns_notify_enabled. " +
				"Only provided fields change. Renames/deletion stay web-only.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain_id":          map[string]any{"type": "integer"},
					"name":               map[string]any{"type": "string", "description": "domain name when id unknown"},
					"monitor_dns":        map[string]any{"type": "boolean"},
					"monitor_whois":      map[string]any{"type": "boolean"},
					"monitor_tls":        map[string]any{"type": "boolean"},
					"cert_notify_days":   map[string]any{"type": "integer"},
					"owner_notify_days":  map[string]any{"type": "integer"},
					"dns_notify_enabled": map[string]any{"type": "boolean"},
				},
				"required": []string{},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				d, err := resolveDomain(ctx, args)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				changed := []string{}
				setBool := func(key string, dst *bool) {
					if v, ok := args[key].(bool); ok {
						*dst = v
						changed = append(changed, key)
					}
				}
				setBool("monitor_dns", &d.MonitorDNS)
				setBool("monitor_whois", &d.MonitorWhois)
				setBool("monitor_tls", &d.MonitorTLS)
				setBool("dns_notify_enabled", &d.DNSNotifyEnabled)
				if v, ok := intArg(args, "cert_notify_days"); ok {
					d.CertNotifyDays = int(v)
					changed = append(changed, "cert_notify_days")
				}
				if v, ok := intArg(args, "owner_notify_days"); ok {
					d.OwnerNotifyDays = int(v)
					changed = append(changed, "owner_notify_days")
				}
				if len(changed) == 0 {
					return jsonStr(map[string]any{"ok": true, "changed": []string{}})
				}
				if err := s.UpdateDomain(ctx, d); err != nil {
					var ve store.ValidationError
					if asValidation(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid domain: " + ve.Error()})
					}
					return "", err
				}
				auditAppendAI(s, "ai_update_domain", "domain", strconv.FormatInt(d.ID, 10), true)
				return jsonStr(map[string]any{"ok": true, "changed": changed, "domain": d.Name})
			},
		},
		{
			Name: "list_domain_reminders",
			Description: "List the reminder rules of a domain (cert/owner expiry thresholds, channel, " +
				"repeat). Use it before add/delete to see what exists.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain_id": map[string]any{"type": "integer"},
					"name":      map[string]any{"type": "string"},
				},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				d, err := resolveDomain(ctx, args)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				rows, err := s.ListDomainReminders(ctx, d.ID)
				if err != nil {
					return "", err
				}
				return jsonStr(rows)
			},
		},
		{
			Name: "add_domain_reminder",
			Description: "Add an expiry reminder for a domain: kind cert|owner, days = threshold " +
				"(notify when expiry is closer), channel = delivery channel name or id (omit for " +
				"in-app only), repeat_days = re-notify interval (0 = once).",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain_id":   map[string]any{"type": "integer"},
					"name":        map[string]any{"type": "string"},
					"kind":        map[string]any{"type": "string", "description": "cert | owner"},
					"days":        map[string]any{"type": "integer"},
					"channel":     map[string]any{"type": "string", "description": "channel name or id (optional)"},
					"repeat_days": map[string]any{"type": "integer"},
				},
				"required": []string{"kind", "days"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				d, err := resolveDomain(ctx, args)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				kind, _ := strArg(args, "kind")
				if kind != "cert" && kind != "owner" {
					return jsonStr(map[string]any{"error": "kind must be cert or owner"})
				}
				days, ok := intArg(args, "days")
				if !ok || days <= 0 {
					return jsonStr(map[string]any{"error": "days must be > 0"})
				}
				chID := int64(0)
				if spec, _ := strArg(args, "channel"); spec != "" {
					chID, err = resolveChannel(ctx, spec)
					if err != nil {
						return jsonStr(map[string]any{"error": err.Error()})
					}
				}
				r := store.DomainReminder{DomainID: d.ID, Kind: kind, Days: int(days), ChannelID: int(chID)}
				if rd, ok := intArg(args, "repeat_days"); ok {
					r.RepeatDays = int(rd)
				}
				id, err := s.CreateDomainReminder(ctx, r)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				auditAppendAI(s, "ai_add_reminder", "reminder", strconv.FormatInt(id, 10), true)
				return jsonStr(map[string]any{"added": true, "reminder_id": id, "kind": kind, "days": int(days)})
			},
		},
		{
			Name: "delete_domain_reminder",
			Description: "Delete one domain reminder (confirm with the user first). Find ids via " +
				"list_domain_reminders.",
			Parameters: map[string]any{
				"type":       "object",
				"properties": map[string]any{"reminder_id": map[string]any{"type": "integer"}},
				"required":   []string{"reminder_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				rid, _ := intArg(args, "reminder_id")
				if err := s.DeleteDomainReminder(ctx, rid); err != nil {
					return jsonStr(map[string]any{"error": "reminder not found", "reminder_id": rid})
				}
				auditAppendAI(s, "ai_delete_reminder", "reminder", strconv.FormatInt(rid, 10), true)
				return jsonStr(map[string]any{"deleted": true, "reminder_id": rid})
			},
		},
		{
			Name: "acknowledge_dns_change",
			Description: "Mark the current DNS records of a domain as the new trusted baseline " +
				"(clears the dns_changed flag) — the 'acknowledge' button of the UI. Use only after " +
				"the operator confirms the change is expected.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"domain_id": map[string]any{"type": "integer"},
					"name":      map[string]any{"type": "string"},
				},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				d, err := resolveDomain(ctx, args)
				if err != nil {
					return jsonStr(map[string]any{"error": err.Error()})
				}
				info, perr := monitor.ProbeDomain(ctx, d.Name)
				if perr != nil {
					return jsonStr(map[string]any{"error": "probe failed: " + perr.Error()})
				}
				sig := monitor.DNSSignature(info.DNS)
				prev, err := s.SetDomainDNSSignature(ctx, d.ID, sig)
				if err != nil {
					return "", err
				}
				auditAppendAI(s, "ai_dns_ack", "domain", strconv.FormatInt(d.ID, 10), true)
				return jsonStr(map[string]any{"ok": true, "domain": d.Name, "previous_signature_changed": prev != sig})
			},
		},
	}
}

// errDomainArgRequired is returned when get_domain_info got neither id nor name.
var errDomainArgRequired = &toolArgError{"domain_id or name required"}

// toolArgError marks argument-validation failures (message is model-facing).
type toolArgError struct{ msg string }

func (e *toolArgError) Error() string { return e.msg }
