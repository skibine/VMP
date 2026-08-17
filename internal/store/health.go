// Package store — health-score read model (latest result per check of a VM).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(7): HealthReadModel; TECH(8): SQLite,JOIN]
// @purpose Serve the "what is the latest status of each check for this VM" query that backs
//
//	both the results endpoint and the K2 health-score. Plane A read path.
//
// @invariants
//   - Returns one row per check of the VM (LEFT JOIN: checks with no result yet appear with
//     empty LatestStatus, so the health layer can treat them as "unknown/pending").
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: health, LatestResultsForVM, VMCheckStatus, latest result, join, read model
// STRUCTURE: ▶ ┌vmID┐ → ○ checks LEFT JOIN (max id per check) → ∑ scan → ⎷ []VMCheckStatus
package store

import (
	"context"
	"database/sql"
	"encoding/json"
	"fmt"
)

// region STRUCT_VMCheckStatus [DOMAIN(7): Health; CONCEPT(7): ReadModel; TECH(6): struct]
// @purpose One check of a VM plus its most recent result (fields empty if never run).
// endregion STRUCT_VMCheckStatus
type VMCheckStatus struct {
	CheckID       int64          `json:"check_id"`
	CheckType     string         `json:"check_type"`
	Enabled       bool           `json:"enabled"`
	LatestTS      string         `json:"latest_ts"`
	LatestStatus  string         `json:"latest_status"` // ok|warn|critical|unknown|""(no run yet)
	LatestLatency float64        `json:"latest_latency_ms"`
	LatestMessage string         `json:"latest_message"`
	LatestDetail  map[string]any `json:"latest_detail,omitempty"`
}

// region FUNC_LatestResultsForVM [DOMAIN(8): Storage; CONCEPT(7]: Read; TECH(8]: SQLite,JOIN]
// @purpose Return each check of the VM joined with its newest check_result row (incl. the detail
//
//	JSON, so callers like the exposures panel can show the last stored findings without a re-scan).
//
// @complexity 5
// endregion FUNC_LatestResultsForVM
func (s *Store) LatestResultsForVM(ctx context.Context, vmID int64) ([]VMCheckStatus, error) {
	const q = `
SELECT c.id, c.check_type, c.enabled,
       COALESCE(r.ts,''), COALESCE(r.status,''), COALESCE(r.latency_ms,0), COALESCE(r.message,''),
       COALESCE(r.detail,'')
FROM checks c
LEFT JOIN check_results r
  ON r.check_id = c.id
 AND r.id = (SELECT MAX(id) FROM check_results WHERE check_id = c.id)
WHERE c.vm_id = ?
ORDER BY c.id ASC`
	rows, err := s.DB.QueryContext(ctx, q, vmID)
	if err != nil {
		return nil, fmt.Errorf("LatestResultsForVM: %w", err)
	}
	defer rows.Close()
	var out []VMCheckStatus
	for rows.Next() {
		var v VMCheckStatus
		var enabled int
		var detailJSON string
		if err := rows.Scan(&v.CheckID, &v.CheckType, &enabled, &v.LatestTS,
			&v.LatestStatus, &v.LatestLatency, &v.LatestMessage, &detailJSON); err != nil {
			return nil, fmt.Errorf("LatestResultsForVM scan: %w", err)
		}
		v.Enabled = enabled != 0
		if detailJSON != "" {
			var d map[string]any
			if err := json.Unmarshal([]byte(detailJSON), &d); err == nil {
				v.LatestDetail = d
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// region FUNC_LatestResultsForDomain [DOMAIN(8): Storage; CONCEPT(7): Read; TECH(8): SQLite,JOIN]
// @purpose Return each check of the DOMAIN joined with its newest check_result row — the mirror of
//
//	LatestResultsForVM for the domain read model. Feeds the AI domain tools (list_domains) so the
//	assistant can report the stored tls/whois/dns status without a live probe.
//
// @complexity 5
// endregion FUNC_LatestResultsForDomain
func (s *Store) LatestResultsForDomain(ctx context.Context, domainID int64) ([]VMCheckStatus, error) {
	const q = `
SELECT c.id, c.check_type, c.enabled,
       COALESCE(r.ts,''), COALESCE(r.status,''), COALESCE(r.latency_ms,0), COALESCE(r.message,''),
       COALESCE(r.detail,'')
FROM checks c
LEFT JOIN check_results r
  ON r.check_id = c.id
 AND r.id = (SELECT MAX(id) FROM check_results WHERE check_id = c.id)
WHERE c.domain_id = ?
ORDER BY c.id ASC`
	rows, err := s.DB.QueryContext(ctx, q, domainID)
	if err != nil {
		return nil, fmt.Errorf("LatestResultsForDomain: %w", err)
	}
	defer rows.Close()
	var out []VMCheckStatus
	for rows.Next() {
		var v VMCheckStatus
		var enabled int
		var detailJSON string
		if err := rows.Scan(&v.CheckID, &v.CheckType, &enabled, &v.LatestTS,
			&v.LatestStatus, &v.LatestLatency, &v.LatestMessage, &detailJSON); err != nil {
			return nil, fmt.Errorf("LatestResultsForDomain scan: %w", err)
		}
		v.Enabled = enabled != 0
		if detailJSON != "" {
			var d map[string]any
			if err := json.Unmarshal([]byte(detailJSON), &d); err == nil {
				v.LatestDetail = d
			}
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// VMExists reports whether a VM with the given id exists (any archive state).
func (s *Store) VMExists(ctx context.Context, vmID int64) (bool, error) {
	var one int
	err := s.DB.QueryRowContext(ctx, `SELECT 1 FROM vms WHERE id=? LIMIT 1`, vmID).Scan(&one)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("VMExists: %w", err)
	}
	return true, nil
}
