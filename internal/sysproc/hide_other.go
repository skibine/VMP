//go:build !windows

package sysproc

import "os/exec"

// Attach is a no-op outside Windows (unix children have no window to hide).
func Attach(cmd *exec.Cmd) {}
