// Package logging — size-rotating file writer (pure stdlib).
//
// region MODULE_CONTRACT [DOMAIN(8): Observability; CONCEPT(8): LogRotation; TECH(7): stdlib,os]
// @purpose Keep vmpulse logs on disk with a bounded footprint (vmpulse.log.N.gz-style chain) so
//
//	headless/windowless deployments (windowsgui builds) still leave a diagnostic trail.
//
// @io NewRotatingWriter(path string, maxBytes int64, backups int) -> io.WriteCloser
// @invariants
//   - Rotation happens BEFORE a write that would exceed maxBytes (the active file never
//     grows past maxBytes + one log line).
//   - The chain is bounded: vmpulse.log, vmpulse.log.1 ... vmpulse.log.<backups>; older files
//     are removed on rotation.
//   - A failed rotation NEVER breaks logging: writes continue into the (overgrown) active file.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: rotating writer, log rotation, vmpulse.log, size limit, backups, file logging
// STRUCTURE: ▶ ┌write┐ → ◇ size+n>max? → ⚡ shift chain (.1←.2 …) → ⊕ append → ⎋ n
package logging

import (
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

// rotatingWriter is a size-rotating log sink (lumberjack-style, stdlib-only).
type rotatingWriter struct {
	mu        sync.Mutex
	path      string
	maxBytes  int64
	backups   int
	file      *os.File
	written   int64
	openErrAt bool
}

// region FUNC_NewRotatingWriter [DOMAIN(8): Observability; CONCEPT(7): FileSink; TECH(6): os]
// @purpose Open (creating dirs) a rotating log file. maxBytes<=0 or backups<=0 disable rotation
//
//	(single growing file) — explicit operator choice, never a crash.
//
// @complexity 4
// endregion FUNC_NewRotatingWriter
func NewRotatingWriter(path string, maxBytes int64, backups int) (*rotatingWriter, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return nil, fmt.Errorf("rotating writer: mkdir: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return nil, fmt.Errorf("rotating writer: open: %w", err)
	}
	st, err := f.Stat()
	written := int64(0)
	if err == nil {
		written = st.Size()
	}
	return &rotatingWriter{path: path, maxBytes: maxBytes, backups: backups, file: f, written: written}, nil
}

// Write appends p, rotating first when the active file would overflow.
func (w *rotatingWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return 0, fmt.Errorf("rotating writer: closed")
	}
	if w.maxBytes > 0 && w.written+int64(len(p)) > w.maxBytes {
		w.rotateLocked()
	}
	n, err := w.file.Write(p)
	w.written += int64(n)
	return n, err
}

// rotateLocked shifts the backup chain and reopens a fresh active file. Errors degrade to
// keep writing into the current file (logging must never die).
func (w *rotatingWriter) rotateLocked() {
	if w.backups <= 0 {
		return
	}
	_ = w.file.Close()
	for i := w.backups; i >= 1; i-- {
		older := fmt.Sprintf("%s.%d", w.path, i)
		if i == w.backups {
			_ = os.Remove(older)
			continue
		}
		_ = os.Rename(fmt.Sprintf("%s.%d", w.path, i), fmt.Sprintf("%s.%d", w.path, i+1))
	}
	_ = os.Rename(w.path, w.path+".1")
	f, err := os.OpenFile(w.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		// Degrade: keep the old handle if reopen failed (file var stays usable when nil-checked).
		return
	}
	w.file = f
	w.written = 0
}

// Close flushes and closes the active file.
func (w *rotatingWriter) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.file == nil {
		return nil
	}
	err := w.file.Close()
	w.file = nil
	return err
}
