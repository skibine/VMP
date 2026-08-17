//go:build linux

// Package install — Linux disk-free reader (Statfs is syscall/Linux-specific; split out so the
// package cross-compiles to Windows/macOS via disk_other.go).
package install

import "syscall"

// region FUNC_diskFreeGB [DOMAIN(6): Posture; CONCEPT(6): Disk; TECH(6): syscall,Statfs]
// @purpose Report free disk on "/" in GB (Linux). Returns 0 on error.
// @complexity 2
// endregion FUNC_diskFreeGB
func diskFreeGB() float64 {
	var stat syscall.Statfs_t
	if err := syscall.Statfs("/", &stat); err != nil {
		return 0
	}
	free := float64(stat.Bavail) * float64(stat.Bsize) / 1e9
	return float64(int(free*100)) / 100
}
