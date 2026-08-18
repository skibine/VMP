// Package ai — fleet mutators (Plane A, low-risk): add a VM or domain to monitoring.
//
// region MODULE_CONTRACT [DOMAIN(8): AI,Config; CONCEPT(8): Mutating; TECH(7): store,audit]
// @purpose Let the assistant fulfill "put Kate-USA on monitoring" / "add example.pro" directly:
//
//	adding a monitoring target is a low-risk mutation (Plane A — no credentials involved), so it
//	executes IMMEDIATELY and lands in the tamper-evident audit chain. Deletions and credential
//	operations stay web-only (behind 2FA/vault) by design.
//
// @invariants
//   - add_vm stores connection coordinates only — NEVER credentials (creds live in the vault, web-only).
//   - add_vm/add_domain auto-provision the same system checks the web UI path creates
//     (liveness + exposures for VMs; whois + tls for domains), so the new target starts monitoring.
//   - Every successful or failed mutation writes an audit entry (ai_add_vm / ai_add_domain).
//
// @rationale
// Q: Why immediate execution instead of the propose/approve queue used for commands?
// A: The approval queue exists for SSH command execution (destructive potential, Plane B). Adding a
//
//	monitor target cannot destroy anything and is trivially reversible in the UI; gating it behind
//	approval would break the conversational flow ("поставь на мониторинг" -> done) that operators
//	expect from a chat frontend, while the audit chain still records who/what/when.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: add_vm, add_domain, fleet mutator, monitoring, audit, ai tools, plane a
// STRUCTURE: ▶ add_vm: ┌{name,hostname,ip,port}┐ → ○ CreateVM → ⊕ EnsureSystem* → ⚡ audit → ⎷ JSON ; add_domain: ┌{name}┐ → ◇ duplicate? → ⊕ EnsureDomainChecks → ⚡ audit → ⎷ JSON
package ai

import (
	"context"
	"errors"
	"net"
	"strconv"
	"strings"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/store"
)

// FleetMutators builds the immediate-mutation tools: add_vm and add_domain.
func FleetMutators(s *store.Store) []Tool {
	return []Tool{
		{
			Name: "add_vm",
			Description: "Add a new host to monitoring — this is how you fulfill 'put <name> on " +
				"monitoring'. Stores name + hostname/ip (+ optional ssh port, default 22) and immediately " +
				"provisions the always-on liveness + security-exposures checks, so monitoring starts " +
				"within a minute. kind: server (default) for servers/VPS, or equipment for anything " +
				"else — routers, cameras, external web panels (a bare IP is NEVER a domain). This does " +
				"NOT store SSH credentials — the operator adds those in the web UI (vault/2FA) if " +
				"interactive access is wanted later.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name":     map[string]any{"type": "string", "description": "short display name, e.g. Kate-USA"},
					"hostname": map[string]any{"type": "string", "description": "IP address or resolvable hostname"},
					"ip":       map[string]any{"type": "string", "description": "IP if known (optional when hostname is an IP)"},
					"port_ssh": map[string]any{"type": "integer", "description": "ssh port (optional, default 22)"},
					"kind":     map[string]any{"type": "string", "description": "server | equipment (default server)"},
				},
				"required": []string{"name", "hostname"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				name, _ := strArg(args, "name")
				hostname, _ := strArg(args, "hostname")
				ip, _ := strArg(args, "ip")
				kind, _ := strArg(args, "kind")
				port := 22
				if p, ok := intArg(args, "port_ssh"); ok && p > 0 && p < 65536 {
					port = int(p)
				}
				if strings.TrimSpace(ip) == "" && isIPLike(hostname) {
					ip = hostname
				}
				vm := store.VM{Name: strings.TrimSpace(name), Hostname: strings.TrimSpace(hostname),
					IP: strings.TrimSpace(ip), PortSSH: port, Kind: store.NormalizeVMKind(kind)}
				id, err := s.CreateVM(ctx, vm)
				if err != nil {
					auditAppendAI(s, "ai_add_vm", "vm", vm.Name, false)
					var ve store.ValidationError
					if errors.As(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid vm: " + ve.Error(), "field": ve.Field})
					}
					return "", err
				}
				_ = s.EnsureSystemLiveness(ctx, id, port)
				_ = s.EnsureSystemExposures(ctx, id)
				auditAppendAI(s, "ai_add_vm", "vm", strconv.FormatInt(id, 10), true)
				return jsonStr(map[string]any{"added": true, "vm_id": id, "name": vm.Name,
					"note": "liveness + exposures checks provisioned; first results within a minute"})
			},
		},
		{
			Name: "archive_vm",
			Description: "Archive a VM/equipment: removes it from the fleet view and stops " +
				"monitoring, but keeps ALL history; reversible from the web UI (archived tab). " +
				"Prefer this over delete_vm whenever the operator may still need the data. " +
				"Ask the operator in chat first.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id":  map[string]any{"type": "integer"},
					"reason": map[string]any{"type": "string", "description": "short why (goes to the audit log)"},
				},
				"required": []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				vm, err := s.GetVM(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": vmID})
				}
				if err := s.ArchiveVM(ctx, vmID); err != nil {
					return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
				}
				auditAppendAI(s, "ai_archive_vm", "vm", strconv.FormatInt(vmID, 10)+" name="+vm.Name, true)
				return jsonStr(map[string]any{"archived": true, "vm_id": vmID, "name": vm.Name,
					"note": "history kept; restore from the web UI archived tab"})
			},
		},
		{
			Name: "delete_vm",
			Description: "PERMANENTLY delete a VM/equipment with ALL its history (checks, results, " +
				"metrics). Irreversible. Use for wrongly-added hosts (e.g. a mistyped IP that was " +
				"never real); use archive_vm when the data may matter later. The tool REFUSES to run " +
				"unless confirm='yes' — get an explicit approval from the operator in chat first, " +
				"then re-call with confirm.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"vm_id": map[string]any{"type": "integer"},
					"confirm": map[string]any{"type": "string", "enum": []string{"yes"},
						"description": "pass 'yes' ONLY after the operator explicitly approved the deletion"},
					"reason": map[string]any{"type": "string", "description": "short why (goes to the audit log)"},
				},
				"required": []string{"vm_id"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				vmID, _ := intArg(args, "vm_id")
				vm, err := s.GetVM(ctx, vmID)
				if err != nil {
					return jsonStr(map[string]any{"error": "vm not found", "vm_id": vmID})
				}
				if c, _ := strArg(args, "confirm"); c != "yes" {
					return jsonStr(map[string]any{"deleted": false,
						"error": "confirmation required: ask the operator, then re-call with confirm='yes'",
						"vm_id": vmID, "name": vm.Name})
				}
				if err := s.DeleteVM(ctx, vmID); err != nil {
					return jsonStr(map[string]any{"error": err.Error(), "vm_id": vmID})
				}
				auditAppendAI(s, "ai_delete_vm", "vm", strconv.FormatInt(vmID, 10)+" name="+vm.Name, true)
				return jsonStr(map[string]any{"deleted": true, "vm_id": vmID, "name": vm.Name})
			},
		},
		{
			Name: "add_domain",
			Description: "Add a domain (e.g. example.pro) to monitoring — registration (whois) and " +
				"certificate (tls) expiry checks are provisioned immediately and reminders follow the " +
				"domain's notify settings. Fails politely when the domain is already monitored.",
			Parameters: map[string]any{
				"type": "object",
				"properties": map[string]any{
					"name": map[string]any{"type": "string", "description": "domain name, e.g. example.pro"},
				},
				"required": []string{"name"},
			},
			Run: func(ctx context.Context, args map[string]any) (string, error) {
				name, _ := strArg(args, "name")
				name = strings.ToLower(strings.TrimPrefix(strings.TrimSpace(name), "www."))
				// Guard before the store error: give the model the actionable redirect (an IP is a
				// VM of kind network/iot/web — whois/dns checks are meaningless for it).
				if net.ParseIP(name) != nil {
					return jsonStr(map[string]any{
						"error": "that is an IP address, not a domain",
						"hint":  "add it as a VM with kind=equipment (router, camera, web panel) via add_vm",
					})
				}
				id, err := s.CreateDomain(ctx, store.Domain{Name: name, MonitorDNS: true, MonitorWhois: true, MonitorTLS: true})
				dup := errors.Is(err, store.ErrDuplicate)
				if err != nil {
					auditAppendAI(s, "ai_add_domain", "domain", name, false)
					if dup {
						return jsonStr(map[string]any{"added": false, "error": "domain already monitored", "name": name})
					}
					var ve store.ValidationError
					if errors.As(err, &ve) {
						return jsonStr(map[string]any{"error": "invalid domain: " + ve.Error(), "field": ve.Field})
					}
					return "", err
				}
				_ = s.EnsureDomainChecks(ctx, id)
				auditAppendAI(s, "ai_add_domain", "domain", strconv.FormatInt(id, 10), true)
				return jsonStr(map[string]any{"added": true, "domain_id": id, "name": name,
					"note": "whois + tls expiry checks provisioned (6h cadence)"})
			},
		},
	}
}

// auditAppendAI records an AI-initiated fleet mutation in the tamper-evident chain (Plane A:
// these mutations never touch credentials). Failures are logged, never propagated — the tool result
// itself is the operator-facing outcome.
func auditAppendAI(s *store.Store, action, targetType, targetID string, success bool) {
	_ = audit.Append(s.DB, nil, audit.Entry{
		Plane: audit.PlaneA, Action: action, TargetType: targetType, TargetID: targetID,
		Success: success,
	})
}

// isIPLike reports whether s looks like a dotted-quad or IPv6 literal (no DNS lookup).
func isIPLike(s string) bool {
	s = strings.TrimSpace(s)
	if s == "" {
		return false
	}
	colons := strings.Count(s, ":")
	if colons >= 2 { // IPv6 literal (heuristic: at least 2 colons)
		return true
	}
	parts := strings.Split(s, ".")
	if len(parts) != 4 {
		return false
	}
	for _, p := range parts {
		if p == "" || len(p) > 3 {
			return false
		}
		if n, err := strconv.Atoi(p); err != nil || n < 0 || n > 255 {
			return false
		}
	}
	return true
}
