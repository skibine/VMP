// Package store — configuration domain models (VMs, checks, domains).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): DomainModel; TECH(8): struct,validation]
// @purpose Define the typed entities persisted in the config schema and their validation,
//
//	so repository and API layers share one source of truth for shape/rules.
//
// @io n/a (types + Validate methods)
// @invariants
//   - JSON columns (tags, params, thresholds) are represented as native Go types and
//     marshalled to TEXT at the repository boundary.
//   - Validate is called by both Create and Update paths.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: models, VM, Check, Domain, validation, tags, params, thresholds
// STRUCTURE: ▶ ┌struct┐ → ○ Validate → 〈field rules〉 → ⊕ error|nil
package store

import (
	"encoding/json"
	"fmt"
	"strings"
	"net"
)

// region STRUCT_ValidationError [DOMAIN(7): Validation; CONCEPT(6): Error; TECH(5): struct]
// @purpose Carry a single field-level validation failure up to the API layer (-> HTTP 400).
// endregion STRUCT_ValidationError
type ValidationError struct {
	Field  string
	Reason string
}

func (e ValidationError) Error() string { return e.Field + ": " + e.Reason }

// region STRUCT_VM [DOMAIN(8): Config; CONCEPT(7): Entity; TECH(7): struct]
// @purpose Represent a managed virtual machine. SSH credentials are NOT stored on the VM
//
//	record (Plane B vault owns those); this holds connection coordinates + metadata.
//
// endregion STRUCT_VM
type VM struct {
	ID                int64    `json:"id"`
	Name              string   `json:"name"`
	DisplayNo         int      `json:"display_no"` // stable ordinal assigned at creation; never renumbered
	Hostname          string   `json:"hostname"`
	IP                string   `json:"ip"`
	PortSSH           int      `json:"port_ssh"`
	SSHUser           string   `json:"ssh_user"`
	AuthType          string   `json:"auth_type"`
	Provider          string   `json:"provider"`
	LocationCountry   string   `json:"location_country"`
	LocationCity      string   `json:"location_city"`
	Tags              []string `json:"tags"`
	GroupID           *int64   `json:"group_id"`
	Notes             string   `json:"notes"`
	CostMonthly       *float64 `json:"cost_monthly"`
	Currency          string   `json:"currency"`
	OwnerUserID       *int64   `json:"owner_user_id"`
	AgentEnabled      bool     `json:"agent_enabled"`
	AgentPort         *int     `json:"agent_port"`
	PrometheusURL     string   `json:"prometheus_url"`
	RecordSSHSessions bool     `json:"record_ssh_sessions"`
	MetricsEnabled    bool     `json:"metrics_enabled"`
	Kind              string   `json:"kind"` // server (default) | equipment (router, camera, web panel, any non-server host)
	AIEnabled         bool     `json:"ai_enabled"`
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
	ArchivedAt        *string  `json:"archived_at"`
	// HasCreds is NOT a stored column — it is computed at list time (vm_credentials row exists) so the
	// UI can show the lock badge without an extra per-VM request.
	HasCreds bool `json:"has_creds"`
}

// region FUNC_VM_Validate [DOMAIN(7): Validation; CONCEPT(7): Rules; TECH(4): pure]
// @purpose Enforce VM invariants: required name/hostname, sane SSH port.
// @complexity 3
// endregion FUNC_VM_Validate
func (v VM) Validate() error {
	if strings.TrimSpace(v.Name) == "" {
		return ValidationError{Field: "name", Reason: "required"}
	}
	if strings.TrimSpace(v.Hostname) == "" {
		return ValidationError{Field: "hostname", Reason: "required"}
	}
	if v.PortSSH < 1 || v.PortSSH > 65535 {
		return ValidationError{Field: "port_ssh", Reason: "must be in 1..65535"}
	}
	if !ValidVMKind(v.Kind) {
		return ValidationError{Field: "kind", Reason: "must be server or equipment"}
	}
	return nil
}

// region STRUCT_Check [DOMAIN(8): Config; CONCEPT(8): Monitoring; TECH(7): struct]
// @purpose Represent a configured check. Targets exactly one of vm_id / domain_id.
// endregion STRUCT_Check
type Check struct {
	ID          int64          `json:"id"`
	VMID        *int64         `json:"vm_id"`
	DomainID    *int64         `json:"domain_id"`
	TargetType  string         `json:"target_type"` // vm | domain
	CheckType   string         `json:"check_type"`  // liveness|ping|tcp|http|whois|tls|dns|dnsbl
	Params      map[string]any `json:"params"`
	IntervalSec int            `json:"interval_sec"`
	Enabled     bool           `json:"enabled"`
	Thresholds  map[string]any `json:"thresholds"`
	System      bool           `json:"system"` // system-managed (auto liveness) — not user-deletable
	CreatedAt   string         `json:"created_at"`
}

// validCheckTypes is the closed set of supported checker types (Plane A engine, next slice).
var validCheckTypes = map[string]struct{}{
	"liveness": {}, "exposures": {}, "ping": {}, "tcp": {}, "http": {}, "whois": {}, "tls": {}, "dns": {}, "dnsbl": {}, "agent": {}, "prom": {},
}

// region FUNC_Check_Validate [DOMAIN(7): Validation; CONCEPT(8): Rules; TECH(5): pure]
// @purpose Enforce check invariants: target/check type sets, positive interval, and
//
//	target<->id consistency (a vm check needs vm_id; a domain check needs domain_id).
//
// @complexity 4
// endregion FUNC_Check_Validate
func (c Check) Validate() error {
	if c.TargetType != "vm" && c.TargetType != "domain" {
		return ValidationError{Field: "target_type", Reason: "must be 'vm' or 'domain'"}
	}
	if _, ok := validCheckTypes[c.CheckType]; !ok {
		return ValidationError{Field: "check_type", Reason: "unsupported type: " + c.CheckType}
	}
	if c.IntervalSec < 1 {
		return ValidationError{Field: "interval_sec", Reason: "must be >= 1"}
	}
	if c.TargetType == "vm" && (c.VMID == nil || *c.VMID == 0) {
		return ValidationError{Field: "vm_id", Reason: "required when target_type=vm"}
	}
	if c.TargetType == "domain" && (c.DomainID == nil || *c.DomainID == 0) {
		return ValidationError{Field: "domain_id", Reason: "required when target_type=domain"}
	}
	return nil
}

// region STRUCT_Domain [DOMAIN(8): Config; CONCEPT(7): Entity; TECH(7): struct]
// @purpose Represent a monitored domain (DNS/whois/TLS checks attach to it).
// endregion STRUCT_Domain
type Domain struct {
	ID             int64  `json:"id"`
	Name           string `json:"name"`
	Registrar      string `json:"registrar"`
	AutoDiscovered bool   `json:"auto_discovered"`
	VMID           *int64 `json:"vm_id"`
	MonitorDNS     bool   `json:"monitor_dns"`
	MonitorWhois   bool   `json:"monitor_whois"`
	MonitorTLS     bool   `json:"monitor_tls"`
	CertNotifyDays  int    `json:"cert_notify_days"`
	OwnerNotifyDays int    `json:"owner_notify_days"`
	CertLastNotified  string `json:"cert_last_notified_at"`
	OwnerLastNotified string `json:"owner_last_notified_at"`
	CertNotifyChannelID  int    `json:"cert_notify_channel_id"`
	OwnerNotifyChannelID int    `json:"owner_notify_channel_id"`
	DNSNotifyEnabled     bool   `json:"dns_notify_enabled"`
	DNSNotifyChannelID   int    `json:"dns_notify_channel_id"`
	DNSLastSignature     string `json:"dns_last_signature"`
	DNSLastNotified      string `json:"dns_last_notified_at"`
	CreatedAt      string `json:"created_at"`
}

// Notification is one in-app notification row (reminder delivery channel "in-app").
type Notification struct {
	ID        int64  `json:"id"`
	Title     string `json:"title"`
	Body      string `json:"body"`
	Kind      string `json:"kind"`
	RefID     *int64 `json:"ref_id"`
	CreatedAt string `json:"created_at"`
	ReadAt    string `json:"read_at"`
}

// DomainReminder is one expiry/change reminder attached to a domain. A domain may have several
// per kind (e.g. cert at 30d and at 7d). repeat_days>0 re-fires while triggered.
type DomainReminder struct {
	ID            int64  `json:"id"`
	DomainID      int64  `json:"domain_id"`
	Kind          string `json:"kind"`           // cert | owner | dns
	Days          int    `json:"days"`           // threshold (0 for dns)
	ChannelID     int    `json:"channel_id"`     // 0 = in-app only
	RepeatDays    int    `json:"repeat_days"`    // 0 = once; >0 = re-notify interval
	LastNotified  string `json:"last_notified_at"`
	CreatedAt     string `json:"created_at"`
}

// region FUNC_Domain_Validate [DOMAIN(7): Validation; CONCEPT(6): Rules; TECH(3): pure]
// @purpose Enforce domain invariants: non-empty name.
// @complexity 2
// endregion FUNC_Domain_Validate
func (d Domain) Validate() error {
	if strings.TrimSpace(d.Name) == "" {
		return ValidationError{Field: "name", Reason: "required"}
	}
	// BUG_FIX_CONTEXT: a bare IP used to be accepted as a "domain" (the operator added a router
	// IP), where whois/dns checks are meaningless. Reject with an actionable message — an IP is
	// monitored as a VM (kind network/iot/web), not a domain.
	if net.ParseIP(strings.TrimSpace(d.Name)) != nil {
		return ValidationError{Field: "name", Reason: "это IP-адрес — добавьте его как ВПС/оборудование, а не домен (IPs belong in a VM of kind equipment, not domains)"}
	}
	return nil
}

// validVMKinds is the closed set of VM kinds: a host is either a server or equipment.
var validVMKinds = map[string]bool{"server": true, "equipment": true}

// ValidVMKind reports whether k is a valid kind; empty is valid too (normalizes to server).
func ValidVMKind(k string) bool { return k == "" || validVMKinds[k] }

// NormalizeVMKind maps "" -> "server" (the default kind everywhere a VM enters the system).
func NormalizeVMKind(k string) string {
	if k == "" {
		return "server"
	}
	return k
}

// marshalJSONcol serializes a value to a TEXT column. nil maps/slices become "{}"/"[]".
func marshalJSONcol(v any) string {
	if v == nil {
		return "{}"
	}
	switch x := v.(type) {
	case nil:
		return "{}"
	case []string:
		if x == nil {
			return "[]"
		}
	case map[string]any:
		if x == nil {
			return "{}"
		}
	}
	b, err := json.Marshal(v)
	if err != nil {
		return "{}"
	}
	return string(b)
}

// unmarshalJSONcol parses a TEXT column into dst; empty/invalid -> zero value (no panic).
func unmarshalJSONcol(s string, dst any) {
	if strings.TrimSpace(s) == "" {
		return
	}
	_ = json.Unmarshal([]byte(s), dst) // best-effort: tests assert round-trip on valid input
}

// ptrString returns *string from a sql.NullString-ish value; helper kept generic.
func ptrString(s string, valid bool) *string {
	if !valid || s == "" {
		return nil
	}
	v := s
	return &v
}

// fmtID is a tiny helper for log lines.
func fmtID(id int64) string { return fmt.Sprintf("%d", id) }
