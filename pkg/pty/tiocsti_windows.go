//go:build windows
// +build windows

package pty

import "os"

// CheckTIOCSTI on Windows is a no-op as TIOCSTI ioctl is a Unix-specific vector.
func CheckTIOCSTI(f *os.File) error {
	return nil
}
