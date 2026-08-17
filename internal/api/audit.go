// Package api — audit-log viewer endpoints (filters, pagination, clear).
//
// region MODULE_CONTRACT [DOMAIN(8): API,Security; CONCEPT(8): AuditViewer; TECH(8): SQL,http]
// @purpose Let the operator browse the tamper-evident event journal in the UI: filter by date /
//
//	category / VM / status / free text, page through it, and purge old rows ("зачем их копить").
//
// @invariants
//   - Reads only; the chain itself is written exclusively by audit.Append.
//   - Clearing rows NEVER breaks VerifyChain: each row's hash covers (prev_hash, own record), so
//     deleting OTHER rows does not invalidate a kept row's stored hash (the chain link of a kept
//     row still matches what was stored at write time). Documented + tested.
//   - page_size is clamped to 1..200; total reflects the FILTERED count (correct page count).
//
// @rationale
// Q: Why category prefixes instead of a category column?
// A: audit_log.action already encodes the family (auth.*, ai_*, ssh_*, tg_chat_*, service.*);
//    a derived category keeps writes unchanged and the migration set empty.
// endregion MODULE_CONTRACT
// GREP_SUMMARY: audit, events, log viewer, filters, pagination, clear, verify chain, category
// STRUCTURE: ▶ GET: ┌query params┐ → ◇ build WHERE → ⚡ COUNT + page SELECT → ⊕ {events,total} ; DELETE: ┌before?┐ → ⚡ DELETE [AND ts<] → ⎋
package api

import (
	"net/http"
	"regexp"
	"strconv"
	"strings"

	"github.com/skibine/vm-pulse/internal/audit"
	"github.com/skibine/vm-pulse/internal/logging"
)

// auditEvent is one row for the viewer (user-friendly field set). VMID is EXTRACTED from the
// detail payload (both "vm=N" and JSON "vm_id":N dialects) so the UI can show which server the
// event touched even when the writer stored it inside detail only.
type auditEvent struct {
	ID         int64  `json:"id"`
	TS         string `json:"ts"`
	Plane      string `json:"plane"`
	Category   string `json:"category"`
	Action     string `json:"action"`
	Success    bool   `json:"success"`
	UserID     any    `json:"user_id"`
	VMID       *int64 `json:"vm_id,omitempty"`
	DomainID   *int64 `json:"domain_id,omitempty"`
	TargetType string `json:"target_type"`
	TargetID   string `json:"target_id"`
	IPAddress  string `json:"ip_address"`
	Detail     string `json:"detail"`
}

// auditCategory maps an action to its viewer category.
func auditCategory(action string) string {
	switch {
	case strings.HasPrefix(action, "alert_fire"):
		return "alert"
	case strings.HasPrefix(action, "auth."):
		return "auth"
	case strings.HasPrefix(action, "ai_"):
		return "ai"
	case strings.HasPrefix(action, "ssh_"):
		return "ssh"
	case strings.HasPrefix(action, "tg_chat_"):
		return "telegram"
	case strings.HasPrefix(action, "service."):
		return "service"
	case strings.HasPrefix(action, "vm_"),
		strings.HasPrefix(action, "domain_"),
		strings.HasPrefix(action, "check_"),
		strings.HasPrefix(action, "alert_rule_"):
		return "config"
	default:
		return "other"
	}
}

// auditCategories lists the filterable categories: each maps to the action-prefix set its SQL
// filter matches (config mutations use several prefixes — one LIKE per prefix, OR-joined).
var auditCategories = map[string][]string{
	"auth":     {"auth.%"},
	"ai":       {"ai_%"},
	"ssh":      {"ssh_%"},
	"telegram": {"tg_chat_%"},
	"service":  {"service.%"},
	"alert":    {"alert_fire%"},
	"config":   {"vm_%", "domain_%", "check_%", "alert_rule_%"},
}

// auditConfig records a successful CONFIG mutation performed through the web UI (Plane A —
// these never touch credentials). Central helper so every mutation lands in the event journal
// with a uniform shape. `detail` carries ids/names for the viewer (never secrets).
func (a *crudAPI) auditConfig(action string, vmID int64, detail string) {
	_ = audit.Append(a.st.DB, a.logger, audit.Entry{
		Plane: audit.PlaneA, Action: action, Success: true, Detail: detail,
	})
}

// registerAudit wires the audit viewer endpoints.
func registerAudit(mux *http.ServeMux, a *crudAPI) {
	mux.HandleFunc("GET /api/audit", a.listAudit)
	mux.HandleFunc("DELETE /api/audit", a.clearAudit)
}

// region FUNC_listAudit [DOMAIN(8): API; CONCEPT(7): Query; TECH(8): SQL]
// @purpose Filtered + paginated event feed: from/to (YYYY-MM-DD), category, vm_id, success, plane,
//
//	q (substring over action/detail/target_id), page (1-based), page_size (default 50, max 200).
//
// @complexity 7
// endregion FUNC_listAudit
func (a *crudAPI) listAudit(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	var where []string
	var args []any

	if from := q.Get("from"); from != "" {
		where = append(where, "ts >= ?")
		args = append(args, from)
	}
	if to := q.Get("to"); to != "" {
		// 'to' is inclusive of the whole day: compare against the next date.
		where = append(where, "ts < date(?, '+1 day')")
		args = append(args, to)
	}
	if cat := q.Get("category"); cat != "" {
		if prefixes, ok := auditCategories[cat]; ok {
			likes := make([]string, 0, len(prefixes))
			for _, p := range prefixes {
				likes = append(likes, "action LIKE ?")
				args = append(args, p)
			}
			where = append(where, "("+strings.Join(likes, " OR ")+")")
		}
	}
	if vm := q.Get("vm_id"); vm == "any" {
		// Direction filter without a specific target: every event that touches SOME server
		// (either detail dialect or a vm-scoped target_type).
		where = append(where, `(detail LIKE '%vm=%' OR detail LIKE '%vm_id%' OR target_type = 'vm')`)
	} else if vm != "" {
		// Two detail dialects exist: key=value ("... vm=3 cmd=...") and JSON ({"vm_id":3,...}).
		// Trailing boundaries (space/comma/brace) stop vm=1 matching vm=12. target_id is exact.
		where = append(where, `(detail LIKE '%vm=' || ? || ' %' OR detail LIKE '%vm=' || ? || ',%'
			OR detail LIKE '%vm_id%:' || ? || ',%' OR detail LIKE '%vm_id%:' || ? || '}%'
			OR target_id = ?)`)
		args = append(args, vm, vm, vm, vm, vm)
	}
	if dom := q.Get("domain_id"); dom == "any" {
		// Direction filter without a specific target: every event that touches SOME domain.
		where = append(where, `(detail LIKE '%domain_id%' OR detail LIKE '%domain%' OR target_type = 'domain')`)
	} else if dom != "" {
		// Domain dialects: "domain_id=5" in config-mutation details, JSON "domain_id":5,
		// and AI tools writing TargetType='domain' + TargetID.
		where = append(where, `(detail LIKE '%domain_id=' || ? || ' %' OR detail LIKE '%domain_id=' || ? || ',%'
			OR detail LIKE '%domain_id%:' || ? || ',%' OR detail LIKE '%domain_id%:' || ? || '}%'
			OR (target_type = 'domain' AND target_id = ?))`)
		args = append(args, dom, dom, dom, dom, dom)
	}
	if s := q.Get("success"); s != "" {
		where = append(where, "success = ?")
		args = append(args, s == "true")
	}
	if p := q.Get("plane"); p == "A" || p == "B" {
		where = append(where, "plane = ?")
		args = append(args, p)
	}
	if sub := strings.TrimSpace(q.Get("q")); sub != "" {
		where = append(where, "(action LIKE ? OR detail LIKE ? OR target_id LIKE ? OR ip_address LIKE ?)")
		like := "%" + sub + "%"
		args = append(args, like, like, like, like)
	}

	whereSQL := ""
	if len(where) > 0 {
		whereSQL = " WHERE " + strings.Join(where, " AND ")
	}

	// Filtered total (independent of paging).
	var total int
	if err := a.st.DB.QueryRowContext(r.Context(),
		"SELECT COUNT(*) FROM audit_log"+whereSQL, args...).Scan(&total); err != nil {
		a.writeErr(w, "listAudit", err)
		return
	}

	pageSize := clampInt(atoiDefault(q.Get("page_size"), 50), 1, 200)
	page := max(1, atoiDefault(q.Get("page"), 1))

	rows, err := a.st.DB.QueryContext(r.Context(),
		`SELECT id, ts, plane, action, success, user_id, target_type, target_id, ip_address, COALESCE(detail,'')
		 FROM audit_log`+whereSQL+` ORDER BY id DESC LIMIT ? OFFSET ?`,
		append(args, pageSize, (page-1)*pageSize)...)
	if err != nil {
		a.writeErr(w, "listAudit", err)
		return
	}
	defer rows.Close()
	events := []auditEvent{}
	for rows.Next() {
		var e auditEvent
		var successInt int
		if err := rows.Scan(&e.ID, &e.TS, &e.Plane, &e.Action, &successInt,
			&e.UserID, &e.TargetType, &e.TargetID, &e.IPAddress, &e.Detail); err != nil {
			a.writeErr(w, "listAudit", err)
			return
		}
		e.Success = successInt == 1
		e.Category = auditCategory(e.Action)
		e.VMID = extractVMID(e.Detail)
		e.DomainID = extractDomainID(e.Detail)
		events = append(events, e)
	}
	if err := rows.Err(); err != nil {
		a.writeErr(w, "listAudit", err)
		return
	}
	logging.LDD(a.logger, 7, "listAudit", "SERVED",
		"events="+strconv.Itoa(len(events))+" total="+strconv.Itoa(total)+" page="+strconv.Itoa(page))
	writeJSON(w, http.StatusOK, map[string]any{
		"events": events, "total": total, "page": page, "page_size": pageSize,
	})
}

// region FUNC_clearAudit [DOMAIN(8): API,Security; CONCEPT(7): Purge; TECH(7): SQL]
// @purpose DELETE /api/audit?before=YYYY-MM-DD — drop rows older than the date (inclusive of the
//
//	day itself is NOT applied: strictly ts < date+1day, i.e. the whole 'before' day goes too).
//	Without ?before the ENTIRE journal is dropped. Chain integrity of kept rows is unaffected
//	(each row hashes only its own record + the prev_hash captured at write time).
//
// @complexity 4
// endregion FUNC_clearAudit
func (a *crudAPI) clearAudit(w http.ResponseWriter, r *http.Request) {
	before := r.URL.Query().Get("before")
	var err error
	deleted := int64(0)
	if before != "" {
		res, e := a.st.DB.ExecContext(r.Context(), `DELETE FROM audit_log WHERE ts < date(?, '+1 day')`, before)
		if e == nil {
			deleted, _ = res.RowsAffected()
		}
		err = e
	} else {
		res, e := a.st.DB.ExecContext(r.Context(), `DELETE FROM audit_log`)
		if e == nil {
			deleted, _ = res.RowsAffected()
		}
		err = e
	}
	if err != nil {
		a.writeErr(w, "clearAudit", err)
		return
	}
	logging.LDD(a.logger, 9, "clearAudit", "CLEARED",
		"rows="+strconv.FormatInt(deleted, 10)+" before="+before)
	writeJSON(w, http.StatusOK, map[string]any{"status": "cleared", "deleted": deleted})
}

// extractVMID pulls the touched server id out of an audit detail payload. Writers use two
// dialects: key=value ("vm=3 cmd=...") and JSON ({"vm_id":3,"rows":24}). Returns nil when absent.
var reAuditVMID = regexp.MustCompile(`(?:"vm_id"\s*:\s*(\d+))|(?:\bvm=(\d+)\b)`)

func extractVMID(detail string) *int64 {
	m := reAuditVMID.FindStringSubmatch(detail)
	if m == nil {
		return nil
	}
	digits := m[1]
	if digits == "" {
		digits = m[2]
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return &n
}

// extractDomainID pulls the touched domain id out of a detail payload ("domain_id=5" /
// JSON "domain_id":5). Returns nil when absent.
var reAuditDomainID = regexp.MustCompile(`(?:"domain_id"\s*:\s*(\d+))|(?:\bdomain_id=(\d+)\b)`)

func extractDomainID(detail string) *int64 {
	m := reAuditDomainID.FindStringSubmatch(detail)
	if m == nil {
		return nil
	}
	digits := m[1]
	if digits == "" {
		digits = m[2]
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n <= 0 {
		return nil
	}
	return &n
}

// atoiDefault parses a positive int query param with a fallback.
func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil || n < 1 {
		return def
	}
	return n
}

// clampInt bounds v into [lo, hi].
func clampInt(v, lo, hi int) int {
	if v < lo {
		return lo
	}
	if v > hi {
		return hi
	}
	return v
}
