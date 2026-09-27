// Package pty provides terminal detection and I/O stream handling
// to prevent TIOCSTI terminal queue injection attacks (V-05).
package pty

import (
	"os"
	"syscall"
	"unsafe"
)

// Detector defines an interface for terminal introspection.
type Detector interface {
	IsTerminal(f *os.File) bool
}

// POSIXDetector detects terminals using standard POSIX ioctl calls.
type POSIXDetector struct{}

// NewDetector creates a new terminal detector.
func NewDetector() *POSIXDetector {
	return &POSIXDetector{}
}

// IsTerminal returns true if the provided file descriptor is attached to an interactive terminal.
func (d *POSIXDetector) IsTerminal(f *os.File) bool {
	if f == nil {
		return false
	}
	fd := f.Fd()

	var termios syscall.Termios
	// SAFETY: SYS_IOCTL with TIOCGETA queries the terminal state for the given file descriptor.
	// The pointer references a valid, stack-allocated syscall.Termios struct.
	// If fd is not a terminal, the kernel simply returns an error (ENOTTY), which is safely handled.
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		fd,
		uintptr(syscall.TIOCGETA),
		uintptr(unsafe.Pointer(&termios)),
	)
	return err == 0
}

// IsStdinTerminal checks if os.Stdin is connected to an interactive terminal.
func IsStdinTerminal() bool {
	return NewDetector().IsTerminal(os.Stdin)
}
