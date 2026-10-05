//go:build windows

package pty

import (
	"os"
	"syscall"
)

// IsTerminal returns true if the provided file is attached to an interactive Windows console.
func (d *POSIXDetector) IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	var mode uint32
	err := syscall.GetConsoleMode(syscall.Handle(f.Fd()), &mode)
	return err == nil
}
