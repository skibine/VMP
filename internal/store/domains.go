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
UPDATE domains SET name=?, registrar=?, auto_discovered=?, vm_id=?, monitor_dns=?, monitor_whois=?, monitor_tls=?
WHERE id=?`,
		d.Name, d.Registrar, toBoolInt(d.AutoDiscovered), nullInt64(d.VMID),
		toBoolInt(d.MonitorDNS), toBoolInt(d.MonitorWhois), toBoolInt(d.MonitorTLS), d.ID)
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

func domainSelectCols() string {
	return `SELECT id, name, registrar, auto_discovered, vm_id, monitor_dns, monitor_whois, monitor_tls, created_at FROM domains`
}

func scanDomain(sc scanner) (Domain, error) {
	var d Domain
	var vmID sql.NullInt64
	var autoDiscovered, monDNS, monWhois, monTLS int
	err := sc.Scan(&d.ID, &d.Name, &d.Registrar, &autoDiscovered, &vmID, &monDNS, &monWhois, &monTLS, &d.CreatedAt)
	if err != nil {
		return d, err
	}
	d.VMID = toInt64Ptr(vmID)
	d.AutoDiscovered = toBool(autoDiscovered)
	d.MonitorDNS = toBool(monDNS)
	d.MonitorWhois = toBool(monWhois)
	d.MonitorTLS = toBool(monTLS)
	return d, nil
}

// isUniqueViolation detects a UNIQUE constraint failure across the modernc driver.
func isUniqueViolation(err error) bool {
	return err != nil && strings.Contains(strings.ToLower(err.Error()), "unique")
}
