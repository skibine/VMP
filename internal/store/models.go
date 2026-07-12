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
	CreatedAt         string   `json:"created_at"`
	UpdatedAt         string   `json:"updated_at"`
	ArchivedAt        *string  `json:"archived_at"`
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
	CheckType   string         `json:"check_type"`  // ping|tcp|http|whois|tls|agent|prom
	Params      map[string]any `json:"params"`
	IntervalSec int            `json:"interval_sec"`
	Enabled     bool           `json:"enabled"`
	Thresholds  map[string]any `json:"thresholds"`
	CreatedAt   string         `json:"created_at"`
}

// validCheckTypes is the closed set of supported checker types (Plane A engine, next slice).
var validCheckTypes = map[string]struct{}{
	"ping": {}, "tcp": {}, "http": {}, "whois": {}, "tls": {}, "agent": {}, "prom": {},
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
	CreatedAt      string `json:"created_at"`
}

// region FUNC_Domain_Validate [DOMAIN(7): Validation; CONCEPT(6): Rules; TECH(3): pure]
// @purpose Enforce domain invariants: non-empty name.
// @complexity 2
// endregion FUNC_Domain_Validate
func (d Domain) Validate() error {
	if strings.TrimSpace(d.Name) == "" {
		return ValidationError{Field: "name", Reason: "required"}
	}
	return nil
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
