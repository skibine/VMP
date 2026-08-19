//go:build !windows

package sysproc

import (
	"errors"
	"io"
	"os/exec"
)

// Attach is a no-op outside Windows (unix children have no window to hide).
func Attach(cmd *exec.Cmd) {}

// ConsoleOut is a Unix no-op (stdio always works there).
func ConsoleOut() (io.Writer, error) { return nil, errors.New("not windows") }
