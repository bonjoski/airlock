//go:build windows
// +build windows

package pty

import "os"

// CheckTIOCSTI on Windows is a no-op as TIOCSTI ioctl is a Unix-specific vector.
func CheckTIOCSTI(f *os.File) error {
	return nil
}

// TIOCSTIRequest returns the platform-appropriate TIOCSTI ioctl opcode.
func TIOCSTIRequest(goos string) uintptr {
	if goos == "linux" {
		return 0x5412
	}
	if goos == "darwin" {
		return 0x80017472
	}
	return 0
}
