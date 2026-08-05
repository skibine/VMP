// Package store — Domain repository (CRUD).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): Repository; TECH(7): database/sql]
// @purpose Persist monitored domains. DNS/whois/TLS checks attach via the checks table.
// @invariants
//   - Create/Update always Validate() first; name is UNIQUE at the DB level.
//   - A duplicate name on Create yields a constraint error (surfaced to API as 409).
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: Domain, repository, CRUD, unique, name, DNS, whois, TLS
// STRUCTURE: ▶ ┌Domain┐ → ○ Validate → ⊕ INSERT/UPDATE → ⎋ id ; List → ∑ scan
package store

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"strings"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
)

// ErrDuplicate is returned when a UNIQUE constraint is violated (e.g. domain name).
var ErrDuplicate = errors.New("store: duplicate")

// region FUNC_CreateDomain [DOMAIN(8): Storage; CONCEPT(7): Create; TECH(7): database/sql]
// @purpose Insert a domain; ErrDuplicate on a repeated name.
// @complexity 5
// endregion FUNC_CreateDomain
func (s *Store) CreateDomain(ctx context.Context, d Domain) (int64, error) {
	if err := d.Validate(); err != nil {
		return 0, err
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO domains (name, registrar, auto_discovered, vm_id, monitor_dns, monitor_whois, monitor_tls)
VALUES (?,?,?,?,?,?,?)`,
		d.Name, d.Registrar, toBoolInt(d.AutoDiscovered), nullInt64(d.VMID),
		toBoolInt(d.MonitorDNS), toBoolInt(d.MonitorWhois), toBoolInt(d.MonitorTLS))
	if err != nil {
		if isUniqueViolation(err) {
			logging.LDD(s.logger, 8, "CreateDomain", "DUPLICATE", d.Name)
			return 0, ErrDuplicate
		}
		logging.LDD(s.logger, 10, "CreateDomain", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("CreateDomain: %w", err)
	}
	id, _ := res.LastInsertId()
	logging.LDD(s.logger, 8, "CreateDomain", "CREATED", fmt.Sprintf("id=%s name=%s", fmtID(id), d.Name))
	return id, nil
}

// region FUNC_GetDomain [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Fetch a single domain by id.
// @complexity 4
// endregion FUNC_GetDomain
func (s *Store) GetDomain(ctx context.Context, id int64) (Domain, error) {
	row := s.DB.QueryRowContext(ctx, domainSelectCols()+` WHERE id = ?`, id)
	d, err := scanDomain(row)
	if err != nil {
		if errors.Is(err, sql.ErrNoRows) {
			return Domain{}, ErrNotFound
		}
		return Domain{}, fmt.Errorf("GetDomain: %w", err)
	}
	return d, nil
}

// region FUNC_ListDomains [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose List all domains ordered by id.
// @complexity 4
// endregion FUNC_ListDomains
func (s *Store) ListDomains(ctx context.Context) ([]Domain, error) {
	rows, err := s.DB.QueryContext(ctx, domainSelectCols()+` ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListDomains: %w", err)
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("ListDomains scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// region FUNC_UpdateDomain [DOMAIN(8): Storage; CONCEPT(7): Update; TECH(7): database/sql]
// @purpose Update mutable domain fields by id (validates first).
// @complexity 5
// endregion FUNC_UpdateDomain
func (s *Store) UpdateDomain(ctx context.Context, d Domain) error {
	if err := d.Validate(); err != nil {
		return err
	}
	res, err := s.DB.ExecContext(ctx, `
UPDATE domains SET name=?, registrar=?, auto_discovered=?, vm_id=?, monitor_dns=?, monitor_whois=?, monitor_tls=?,
	cert_notify_days=?, owner_notify_days=?, cert_notify_channel_id=?, owner_notify_channel_id=?,
	dns_notify_enabled=?, dns_notify_channel_id=?
WHERE id=?`,
		d.Name, d.Registrar, toBoolInt(d.AutoDiscovered), nullInt64(d.VMID),
		toBoolInt(d.MonitorDNS), toBoolInt(d.MonitorWhois), toBoolInt(d.MonitorTLS),
		d.CertNotifyDays, d.OwnerNotifyDays, d.CertNotifyChannelID, d.OwnerNotifyChannelID,
		toBoolInt(d.DNSNotifyEnabled), d.DNSNotifyChannelID, d.ID)
	if err != nil {
		if isUniqueViolation(err) {
			return ErrDuplicate
		}
		return fmt.Errorf("UpdateDomain: %w", err)
	}
	return rowsAffected(res, "UpdateDomain", d.ID)
}

// region FUNC_DeleteDomain [DOMAIN(8): Storage; CONCEPT(7): Delete; TECH(5): database/sql]
// @purpose Physically delete a domain.
// @complexity 3
// endregion FUNC_DeleteDomain
func (s *Store) DeleteDomain(ctx context.Context, id int64) error {
	res, err := s.DB.ExecContext(ctx, `DELETE FROM domains WHERE id=?`, id)
	if err != nil {
		return fmt.Errorf("DeleteDomain: %w", err)
	}
	return rowsAffected(res, "DeleteDomain", id)
}

// region FUNC_ListDomainsWithReminders [DOMAIN(8): Alerting; CONCEPT(7): DomainExpiry; TECH(6): database/sql]
// @purpose Return domains that have at least one expiry reminder threshold set (>0).
// @complexity 4
// endregion FUNC_ListDomainsWithReminders
func (s *Store) ListDomainsWithReminders(ctx context.Context) ([]Domain, error) {
	rows, err := s.DB.QueryContext(ctx, domainSelectCols()+
		` WHERE cert_notify_days>0 OR owner_notify_days>0 OR dns_notify_enabled=1 ORDER BY id ASC`)
	if err != nil {
		return nil, fmt.Errorf("ListDomainsWithReminders: %w", err)
	}
	defer rows.Close()
	var out []Domain
	for rows.Next() {
		d, err := scanDomain(rows)
		if err != nil {
			return nil, fmt.Errorf("ListDomainsWithReminders scan: %w", err)
		}
		out = append(out, d)
	}
	return out, rows.Err()
}

// region FUNC_MarkDomainNotified [DOMAIN(8): Alerting; CONCEPT(7): Dedup; TECH(6): database/sql]
// @purpose Stamp the last-notified timestamp for a domain's cert or owner expiry reminder so the
//
//	evaluator does not re-fire within the renotify window. kind = "cert" | "owner".
//
// @complexity 3
// endregion FUNC_MarkDomainNotified
func (s *Store) MarkDomainNotified(ctx context.Context, id int64, kind string) error {
	col := "cert_last_notified_at"
	if kind == "owner" {
		col = "owner_last_notified_at"
	}
	now := time.Now().UTC().Format(time.RFC3339Nano)
	_, err := s.DB.ExecContext(ctx, `UPDATE domains SET `+col+`=? WHERE id=?`, now, id)
	if err != nil {
		return fmt.Errorf("MarkDomainNotified: %w", err)
	}
	return nil
}

// region FUNC_SetDomainDNSSignature [DOMAIN(8): Alerting; CONCEPT(7): DNSChange; TECH(6): database/sql]
// @purpose Persist the latest DNS-record signature for a domain (baseline on first probe; the
//
//	evaluator compares against it to detect changes). Returns the previous signature (empty if none).
//
// @complexity 4
// endregion FUNC_SetDomainDNSSignature
func (s *Store) SetDomainDNSSignature(ctx context.Context, id int64, sig string) (prev string, err error) {
	var prevNS sql.NullString
	if e := s.DB.QueryRowContext(ctx, `SELECT dns_last_signature FROM domains WHERE id=?`, id).Scan(&prevNS); e != nil {
		return "", fmt.Errorf("SetDomainDNSSignature read: %w", e)
	}
	if _, e := s.DB.ExecContext(ctx, `UPDATE domains SET dns_last_signature=? WHERE id=?`, sig, id); e != nil {
		return "", fmt.Errorf("SetDomainDNSSignature write: %w", e)
	}
	return prevNS.String, nil
}

func domainSelectCols() string {
	return `SELECT id, name, registrar, auto_discovered, vm_id, monitor_dns, monitor_whois, monitor_tls,
		cert_notify_days, owner_notify_days, cert_last_notified_at, owner_last_notified_at,
		cert_notify_channel_id, owner_notify_channel_id, dns_notify_enabled, dns_notify_channel_id,
		dns_last_signature, dns_last_notified_at, created_at FROM domains`
}

func scanDomain(sc scanner) (Domain, error) {
	var d Domain
	var vmID sql.NullInt64
	var autoDiscovered, monDNS, monWhois, monTLS, dnsEnabled int
	var certLast, ownerLast, dnsLastNotif, dnsSig sql.NullString
	err := sc.Scan(&d.ID, &d.Name, &d.Registrar, &autoDiscovered, &vmID, &monDNS, &monWhois, &monTLS,
		&d.CertNotifyDays, &d.OwnerNotifyDays, &certLast, &ownerLast,
		&d.CertNotifyChannelID, &d.OwnerNotifyChannelID, &dnsEnabled, &d.DNSNotifyChannelID,
		&dnsSig, &dnsLastNotif, &d.CreatedAt)
	if err != nil {
		return d, err
	}
	d.VMID = toInt64Ptr(vmID)
	d.AutoDiscovered = toBool(autoDiscovered)
	d.MonitorDNS = toBool(monDNS)
	d.MonitorWhois = toBool(monWhois)
	d.MonitorTLS = toBool(monTLS)
	d.CertLastNotified = certLast.String
	d.OwnerLastNotified = ownerLast.String
	d.DNSNotifyEnabled = toBool(dnsEnabled)
	d.DNSLastSignature = dnsSig.String
	d.DNSLastNotified = dnsLastNotif.String
	return d, nil
}

// isUniqueViolation detects a UNIQUE constraint failure across the modernc driver.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
