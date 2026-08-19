//go:build windows

package sysproc

import (
	"os/exec"
	"syscall"
)

// CREATE_NO_WINDOW: the child gets no console of its own (mutually exclusive with
// CREATE_NEW_CONSOLE). HideWindow additionally suppresses any inherited-console UI.
// Stdout/Stderr pipe capture is unaffected.
const createNoWindow = 0x08000000

// Attach makes the command invisible on GUI-subsystem builds.
func Attach(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{HideWindow: true, CreationFlags: createNoWindow}
}
