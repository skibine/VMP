//go:build windows

// Package install — Windows disk-free reader via GetDiskFreeSpaceEx (the disk_other.go stub is
// excluded for windows via its build constraint, so this is the windows impl).
package install

import "golang.org/x/sys/windows"

// region FUNC_diskFreeGB [DOMAIN(6): Posture; CONCEPT(6): Disk; TECH(7): win32,GetDiskFreeSpaceEx]
// @purpose Report free disk on the system drive in GB (Windows). Returns 0 on error.
// @complexity 2
// endregion FUNC_diskFreeGB
func diskFreeGB() float64 {
	path, err := windows.UTF16PtrFromString(`C:\`)
	if err != nil {
		return 0
	}
	var free uint64
	if err := windows.GetDiskFreeSpaceEx(path, &free, nil, nil); err != nil {
		return 0
	}
	gb := float64(free) / 1e9
	return float64(int(gb*100)) / 100
}
