// Package audit implements the tamper-evident audit log for VM Pulse.
//
// region MODULE_CONTRACT [DOMAIN(9): Security; CONCEPT(8): TamperEvidence; TECH(8): sha256,chain]
// @purpose Provide an append-only, hash-chained audit trail so that any retrospective
//
//	modification of a past event is detectable. Both Plane A (always-on service
//	events) and Plane B (gated admin/AI actions) write here.
//
// @io (db *sql.DB, logger, Entry) -> error ; VerifyChain(db) -> error
// @uses crypto/sha256, encoding/hex, encoding/json, database/sql
// @invariants
//   - Each row's hash = sha256(prev_hash || canonical_json(record)).
//   - The first row's prev_hash is the empty string.
//   - VerifyChain recomputes every hash in order; any mismatch means tampering.
//
// @rationale
//
//	Q: Why hash over prev_hash || json instead of just the row?
//	A: Including prev_hash makes the chain ordered and backdating-resistant; recomputing
//	   from genesis detects any single-field mutation anywhere in history.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: audit, tamper-evident, prev_hash, sha256, chain, plane, verify, integrity
// STRUCTURE: ▶ ┌Entry┐ → ○ read last hash → ⊕ canonical_json → ⚡ sha256(prev||json) → ∑ insert → ⎷ chain
package audit

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"log/slog"
	"time"

	"github.com/skibine/vm-pulse/internal/logging"
)

// Plane constants. Plane A = always-on monitoring/service events (no master passphrase).
// Plane B = gated interactive actions (web-SSH, AI mutating, admin).
const (
	PlaneA = "A"
	PlaneB = "B"
)

// region STRUCT_Entry [DOMAIN(9): Security; CONCEPT(7): AuditRecord; TECH(7): struct]
// @purpose Carry the logical content of an audit event before it is hashed and persisted.
// endregion STRUCT_Entry
type Entry struct {
	UserID     any    `json:"user_id"` // int or nil (system)
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	Detail     string `json:"detail"` // JSON string
	Success    bool   `json:"success"`
	Plane      string `json:"plane"` // "A" | "B"
}

// hashRecord is the canonical, stable-order struct hashed into the chain. Field order is
// fixed so the JSON (and thus the hash) is deterministic.
type hashRecord struct {
	TS         string `json:"ts"`
	UserID     any    `json:"user_id"`
	Action     string `json:"action"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	IPAddress  string `json:"ip_address"`
	UserAgent  string `json:"user_agent"`
	Detail     string `json:"detail"`
	Success    bool   `json:"success"`
	Plane      string `json:"plane"`
	PrevHash   string `json:"prev_hash"`
}

// region FUNC_Append [DOMAIN(9): Security; CONCEPT(8): Append; TECH(8): sha256,sql]
// @purpose Append one tamper-evident record to audit_log, chaining it to the previous hash.
// @io (db *sql.DB, logger *slog.Logger, e Entry) -> error
// @complexity 6
// @invariants
//   - Plane defaults to PlaneA if empty.
//   - On success the row is durable and part of the verifiable chain.
//
// endregion FUNC_Append
func Append(db *sql.DB, logger *slog.Logger, e Entry) error {
	if e.Plane == "" {
		e.Plane = PlaneA
	}
	prev, err := lastHash(db)
	if err != nil {
		logging.LDD(logger, 10, "Append", "PREV_HASH_FAIL", err.Error())
		return fmt.Errorf("audit: read prev hash: %w", err)
	}
	ts := time.Now().UTC().Format(time.RFC3339Nano)
	rec := hashRecord{
		TS: ts, UserID: e.UserID, Action: e.Action, TargetType: e.TargetType,
		TargetID: e.TargetID, IPAddress: e.IPAddress, UserAgent: e.UserAgent,
		Detail: e.Detail, Success: e.Success, Plane: e.Plane, PrevHash: prev,
	}
	canon, err := json.Marshal(rec)
	if err != nil {
		return fmt.Errorf("audit: marshal: %w", err)
	}
	sum := sha256.Sum256([]byte(prev + string(canon)))
	hash := hex.EncodeToString(sum[:])

	var uid any = e.UserID
	_, err = db.ExecContext(context.Background(), `
		INSERT INTO audit_log (ts, user_id, action, target_type, target_id, ip_address, user_agent, detail, success, prev_hash, hash, plane)
		VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
		ts, uid, e.Action, e.TargetType, e.TargetID, e.IPAddress, e.UserAgent,
		e.Detail, boolToInt(e.Success), prev, hash, e.Plane)
	if err != nil {
		logging.LDD(logger, 10, "Append", "INSERT_FAIL", err.Error())
		return fmt.Errorf("audit: insert: %w", err)
	}
	logging.LDD(logger, 9, "Append", "APPENDED",
		fmt.Sprintf("action=%s plane=%s success=%v hash=%s", e.Action, e.Plane, e.Success, shortHash(hash)))
	return nil
}

// region FUNC_VerifyChain [DOMAIN(9): Security; CONCEPT(8): Integrity; TECH(8): sha256]
// @purpose Recompute every hash from genesis in order and return the first mismatch.
// @io (db *sql.DB) -> error  (nil = chain intact)
// @complexity 6
// @invariants
//   - Reads rows in id order; prev_hash linkage is checked implicitly by recompute.
//
// endregion FUNC_VerifyChain
func VerifyChain(db *sql.DB) error {
	rows, err := db.QueryContext(context.Background(), `
		SELECT id, ts, user_id, action, target_type, target_id, ip_address, user_agent, detail, success, plane, prev_hash, hash
		FROM audit_log ORDER BY id ASC`)
	if err != nil {
		return fmt.Errorf("audit: query: %w", err)
	}
	defer rows.Close()
	for rows.Next() {
		var id int
		var rec hashRecord
		var storedHash string
		var successInt int
		var uid sql.NullInt64
		if err := rows.Scan(&id, &rec.TS, &uid, &rec.Action, &rec.TargetType, &rec.TargetID,
			&rec.IPAddress, &rec.UserAgent, &rec.Detail, &successInt, &rec.Plane, &rec.PrevHash, &storedHash); err != nil {
			return fmt.Errorf("audit: scan id=%d: %w", id, err)
		}
		rec.Success = successInt == 1
		rec.UserID = nilUserID(uid)
		canon, _ := json.Marshal(rec)
		sum := sha256.Sum256([]byte(rec.PrevHash + string(canon)))
		want := hex.EncodeToString(sum[:])
		if want != storedHash {
			return fmt.Errorf("audit: tamper detected at id=%d (stored=%s want=%s)", id, shortHash(storedHash), shortHash(want))
		}
	}
	return rows.Err()
}

// lastHash returns the hash of the most recent audit row, or "" if the table is empty.
func lastHash(db *sql.DB) (string, error) {
	var h string
	err := db.QueryRow(`SELECT hash FROM audit_log ORDER BY id DESC LIMIT 1`).Scan(&h)
	if err == sql.ErrNoRows {
		return "", nil
	}
	if err != nil {
		return "", err
	}
	return h, nil
}

func boolToInt(b bool) int {
	if b {
		return 1
	}
	return 0
}

func nilUserID(uid sql.NullInt64) any {
	if !uid.Valid {
		return nil
	}
	return uid.Int64
}

func shortHash(h string) string {
	if len(h) <= 8 {
		return h
	}
	return h[:8]
}
