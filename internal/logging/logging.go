// Package logging configures structured logging (slog) and provides the
// Log-Driven-Development (LDD) helper used across VM Pulse.
//
// region MODULE_CONTRACT [DOMAIN(9): Observability; CONCEPT(8): LDD; TECH(9): slog]
// @purpose Give every module a uniform, IMP-ranked log line format so AI agents and
//
//	humans can trace execution paths and the "AI belief state" without reading
//	the full codebase.
//
// @io (level slog.Leveler, writers ...io.Writer) -> *slog.Logger
// @uses log/slog, fmt
// @invariants
//   - Setup NEVER returns a nil logger.
//   - LDD ALWAYS emits a message containing the literal token "[IMP:N]".
//   - IMP>=9 is mapped to Warn so AI-belief / critical business logs always surface.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: logging, slog, LDD, IMP, telemetry, trace, structured logs
// STRUCTURE: ▶ ┌level+writers┐ → ○ NewTextHandler(MultiWriter) → ⊕ slog.Logger → ⎷ LDD(msg=[IMP:N])
package logging

import (
	"fmt"
	"io"
	"log/slog"
	"strings"
)

// impToLevel maps the LDD importance scale to slog levels.
// IMP 1-3 Debug, 4-8 Info, 9-10 Warn.
func impToLevel(imp int) slog.Level {
	switch {
	case imp >= 9:
		return slog.LevelWarn
	case imp >= 4:
		return slog.LevelInfo
	default:
		return slog.LevelDebug
	}
}

// region FUNC_Setup [DOMAIN(9): Observability; CONCEPT(7): LoggerConfig; TECH(9): slog]
// @purpose Build a configured slog.Logger writing to one or more writers (stdout + file
//
//	in production, a buffer in tests) so LDD telemetry is capturable everywhere.
//
// @io (level slog.Leveler, writers ...io.Writer) -> *slog.Logger
// @complexity 3
// endregion FUNC_Setup
func Setup(level slog.Leveler, writers ...io.Writer) *slog.Logger {
	var w io.Writer = io.Discard
	if len(writers) == 1 {
		w = writers[0]
	} else if len(writers) > 1 {
		w = io.MultiWriter(writers...)
	}
	h := slog.NewTextHandler(w, &slog.HandlerOptions{Level: level})
	return slog.New(h)
}

// region FUNC_LDD [DOMAIN(9): Observability; CONCEPT(8): LDD; TECH(8): slog]
// @purpose Emit a Log-Driven-Development line in the canonical format
//
//	"[IMP:N][Func][Block] msg" with an explicit imp attribute, so Semantic Trace
//	Verification (grep "[IMP:") works uniformly across Go and tests.
//
// @io (logger *slog.Logger, imp int, fn, block, msg string, attrs ...slog.Attr)
// @complexity 4
// @invariants
//   - A nil logger is a no-op (safe to call from half-initialized components).
//   - The message string ALWAYS starts with "[IMP:N]".
//
// endregion FUNC_LDD
func LDD(logger *slog.Logger, imp int, fn, block, msg string, attrs ...slog.Attr) {
	if logger == nil {
		return
	}
	msg = strings.TrimSpace(msg)
	level := impToLevel(imp)
	full := fmt.Sprintf("[IMP:%d][%s][%s] %s", imp, fn, block, msg)
	attrs = append(attrs, slog.Int("imp", imp))
	switch len(attrs) {
	case 1:
		logger.LogAttrs(nil, level, full, attrs[0])
	default:
		logger.LogAttrs(nil, level, full, attrs...)
	}
}
