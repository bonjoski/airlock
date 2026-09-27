// Package pty provides terminal detection and I/O stream handling
// to prevent TIOCSTI terminal queue injection attacks (V-05).
package pty

import "os"

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

// IsStdinTerminal checks if os.Stdin is connected to an interactive terminal.
func IsStdinTerminal() bool {
	return NewDetector().IsTerminal(os.Stdin)
}
