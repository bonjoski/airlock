//go:build !windows
// +build !windows

package pty

import (
	"errors"
	"os"
	"syscall"
	"unsafe"
)

// TIOCSTI constant across POSIX kernels
const (
	// TIOCSTI Linux / Darwin ioctl request code
	TIOCSTI_DARWIN = 0x80017417
	TIOCSTI_LINUX  = 0x5412
)

// CheckTIOCSTI attempts to push a character into the terminal buffer to test
// if the terminal queue injection vulnerability (V-05) is actively neutralized.
// If the sandbox or kernel properly blocks it, it returns an error (EPERM, ENOTTY, or EIO).
func CheckTIOCSTI(f *os.File) error {
	if f == nil {
		return errors.New("file descriptor is nil")
	}

	char := byte('\n')
	// We test standard TIOCSTI ioctl
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		TIOCSTI_DARWIN,
		uintptr(unsafe.Pointer(&char)),
	)
	if err != 0 {
		return err
	}
	return nil
}
