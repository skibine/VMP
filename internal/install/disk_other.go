//go:build !linux && !windows

// Package install — disk-free stub for non-Linux platforms (the audit is Linux-first; disk reads
// gracefully report 0 elsewhere). Keeps the package cross-compilable.
package install

func diskFreeGB() float64 { return 0 }
