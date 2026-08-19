//go:build windows

package sysproc

import (
	"io"
	"os"
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

// ConsoleOut attaches to the PARENT console (when the GUI-subsystem binary was launched from
// cmd.exe/PowerShell) and opens CONOUT$ for writing. This is what makes `vmpulse doctor`
// actually print in a terminal: a windowsgui process is born without stdio handles, so
// os.Stdout goes nowhere until we attach and reopen the console buffer.
func ConsoleOut() (io.Writer, error) {
	r, _, err := procAttachConsole.Call(attachParentProcess)
	if r == 0 {
		return nil, err
	}
	return os.OpenFile("CONOUT$", os.O_WRONLY, 0)
}

var (
	kernel32            = syscall.NewLazyDLL("kernel32.dll")
	procAttachConsole   = kernel32.NewProc("AttachConsole")
	attachParentProcess = uintptr(0xFFFFFFFF) // ATTACH_PARENT_PROCESS
)
