// Package store — check_results repository (Plane A writes).
//
// region MODULE_CONTRACT [DOMAIN(8): Storage; CONCEPT(8): Metrics; TECH(8): database/sql]
// @purpose Persist the outcome of every executed check and serve "latest N" reads plus a
//
//	time-based retention delete. Plane A owns these writes (no credential dependency).
//
// @invariants
//   - status is one of: ok | warn | critical | unknown (enforced by checkers, not by DB).
//   - idx(check_id, ts DESC) backs ListRecentResults.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: check_results, InsertCheckResult, ListRecentResults, retention, metrics, Plane A
// STRUCTURE: ▶ ┌result┐ → ○ INSERT → ⎋ id ; List → ORDER BY ts DESC LIMIT n ; Retention → DELETE
package store

import (
	"context"
	"fmt"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
)

// region STRUCT_CheckResult [DOMAIN(8): Metrics; CONCEPT(7): Record; TECH(7): struct]
// @purpose One executed-check outcome written by the monitoring engine.
// endregion STRUCT_CheckResult
type CheckResult struct {
	ID        int64          `json:"id"`
	CheckID   int64          `json:"check_id"`
	TS        string         `json:"ts"`
	Status    string         `json:"status"`
	LatencyMS float64        `json:"latency_ms"`
	Message   string         `json:"message"`
	Detail    map[string]any `json:"detail"`
}

// region FUNC_InsertCheckResult [DOMAIN(8): Storage; CONCEPT(7): Write; TECH(6): database/sql]
// @purpose Append one check result row.
// @complexity 3
// endregion FUNC_InsertCheckResult
func (s *Store) InsertCheckResult(ctx context.Context, checkID int64, status string, latencyMS float64, message string, detail map[string]any) (int64, error) {
	if detail == nil {
		detail = map[string]any{}
	}
	res, err := s.DB.ExecContext(ctx, `
INSERT INTO check_results (check_id, status, latency_ms, message, detail)
VALUES (?,?,?,?,?)`, checkID, status, latencyMS, message, marshalJSONcol(detail))
	if err != nil {
		logging.LDD(s.logger, 10, "InsertCheckResult", "INSERT_FAIL", err.Error())
		return 0, fmt.Errorf("InsertCheckResult: %w", err)
	}
	id, _ := res.LastInsertId()
	return id, nil
}

// region FUNC_ListRecentResults [DOMAIN(8): Storage; CONCEPT(6): Read; TECH(6): database/sql]
// @purpose Return the most recent `limit` results for a check (newest first).
// @complexity 3
// endregion FUNC_ListRecentResults
func (s *Store) ListRecentResults(ctx context.Context, checkID int64, limit int) ([]CheckResult, error) {
	if limit <= 0 {
		limit = 10
	}
	rows, err := s.DB.QueryContext(ctx, `
SELECT id, check_id, ts, status, latency_ms, message, detail
FROM check_results WHERE check_id=? ORDER BY ts DESC, id DESC LIMIT ?`, checkID, limit)
	// BUG_FIX_CONTEXT: ts has millisecond precision (table default) — bursts of inserts in one
	// millisecond tied on ts and returned arbitrary order; id (AUTOINCREMENT) is the stable
	// newest-first tiebreak (broke fast CI runners).
	if err != nil {
		return nil, fmt.Errorf("ListRecentResults: %w", err)
	}
	defer rows.Close()
	var out []CheckResult
	for rows.Next() {
		var r CheckResult
		var detail string
		if err := rows.Scan(&r.ID, &r.CheckID, &r.TS, &r.Status, &r.LatencyMS, &r.Message, &detail); err != nil {
			return nil, fmt.Errorf("ListRecentResults scan: %w", err)
		}
		r.Detail = map[string]any{}
		unmarshalJSONcol(detail, &r.Detail)
		out = append(out, r)
	}
	return out, rows.Err()
}

// region FUNC_RetentionDeleteResults [DOMAIN(8): Storage; CONCEPT(7): Retention; TECH(6): database/sql]
// @purpose Delete check_results older than `beforeDays` days; return rows deleted.
// @complexity 3
// endregion FUNC_RetentionDeleteResults
func (s *Store) RetentionDeleteResults(ctx context.Context, beforeDays int) (int64, error) {
	cutoff := time.Now().UTC().AddDate(0, 0, -beforeDays).Format(time.RFC3339Nano)
	res, err := s.DB.ExecContext(ctx, `DELETE FROM check_results WHERE ts < ?`, cutoff)
	if err != nil {
		return 0, fmt.Errorf("RetentionDeleteResults: %w", err)
	}
	n, _ := res.RowsAffected()
	logging.LDD(s.logger, 8, "RetentionDeleteResults", "PRUNED", fmt.Sprintf("days=%d deleted=%d", beforeDays, n))
	return n, nil
}
