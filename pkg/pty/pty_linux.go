//go:build !darwin

package pty

import (
	"os"
	"syscall"
	"unsafe"
)

// IsTerminal returns true if the provided file descriptor is attached to an interactive terminal on Linux.
func (d *POSIXDetector) IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fd := f.Fd()

	var termios syscall.Termios
	// SAFETY: SYS_IOCTL with TCGETS queries terminal state on Linux for a valid file descriptor.
	// The pointer references a valid, stack-allocated syscall.Termios struct.
	// If fd is not a terminal, the kernel returns ENOTTY, which is safely handled.
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		uintptr(syscall.TCGETS),
		uintptr(unsafe.Pointer(&termios)),
	)
	return err == 0
}
