// Package store — nullable column helpers.
//
// region MODULE_CONTRACT [DOMAIN(6): Storage; CONCEPT(6): SQL; TECH(6): database/sql]
// @purpose Bridge Go pointer/bool fields and SQLite nullable columns without panics.
// @invariants
//   - null* helpers never panic on nil input.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: nullable, sql, helper, pointer, bool
// STRUCTURE: ▶ ┌ptr┐ → 〈nil? Invalid : Valid〉 → ⎷ sql.Null*
package store

import "database/sql"

func nullInt64(p *int64) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: *p, Valid: true}
}

func nullInt(p *int) sql.NullInt64 {
	if p == nil {
		return sql.NullInt64{}
	}
	return sql.NullInt64{Int64: int64(*p), Valid: true}
}

func nullFloat64(p *float64) sql.NullFloat64 {
	if p == nil {
		return sql.NullFloat64{}
	}
	return sql.NullFloat64{Float64: *p, Valid: true}
}

func nullString(p *string) sql.NullString {
	if p == nil {
		return sql.NullString{}
	}
	return sql.NullString{String: *p, Valid: true}
}

func toBool(i int) bool { return i != 0 }

func toIntPtr(n sql.NullInt64) *int {
	if !n.Valid {
		return nil
	}
	v := int(n.Int64)
	return &v
}

func toInt64Ptr(n sql.NullInt64) *int64 {
	if !n.Valid {
		return nil
	}
	v := n.Int64
	return &v
}

func toFloat64Ptr(n sql.NullFloat64) *float64 {
	if !n.Valid {
		return nil
	}
	v := n.Float64
	return &v
}

func toStrPtr(n sql.NullString) *string {
	if !n.Valid {
		return nil
	}
	v := n.String
	return &v
}
