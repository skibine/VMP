// Package sysproc — cross-platform subprocess visibility control.
//
// region MODULE_CONTRACT [DOMAIN(8): Platform; CONCEPT(7): SubprocessWindows; TECH(7): exec,syscall]
// @purpose Keep GUI-subsystem builds (-H=windowsgui) truly windowless: any spawned child
//
//	process (ping.exe during liveness checks, netstat/net session in doctor) otherwise
//	FLASHES its own console window at every invocation - the "6 black windows at startup"
//	report on a 6-VM fleet.
//
// @invariants
//   - Attach is a no-op on non-Windows platforms (no behavior change for linux/darwin).
//   - On Windows every attached child gets CREATE_NO_WINDOW|HideWindow: no console flash,
//     output capture (Stdout/Stderr pipes) keeps working unchanged.
//
// endregion MODULE_CONTRACT
// GREP_SUMMARY: sysproc, hide window, CREATE_NO_WINDOW, windowsgui, ping.exe flash, console
// STRUCTURE: ▶ ┌cmd┐ → ○ Attach → 〈windows? ⚡ SysProcAttr{HideWindow, CREATE_NO_WINDOW} : nop〉
package sysproc
