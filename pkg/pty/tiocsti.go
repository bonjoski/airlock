//go:build !windows
// +build !windows

package pty

import (
	"errors"
	"os"
	"runtime"
	"syscall"
	"unsafe"
)

// TIOCSTI constant across POSIX kernels
const (
	// TIOCSTI Darwin/BSD (_IOW('t', 114, char)) and Linux ioctl request codes
	TIOCSTI_DARWIN = 0x80017472
	TIOCSTI_LINUX  = 0x5412
)

// TIOCSTIRequest returns the platform-appropriate TIOCSTI ioctl opcode.
func TIOCSTIRequest(goos string) uintptr {
	if goos == "linux" {
		return TIOCSTI_LINUX
	}
	return TIOCSTI_DARWIN
}

// CheckTIOCSTI attempts to push a character into the terminal buffer to test
// if the terminal queue injection vulnerability (V-05) is actively neutralized.
// If the sandbox or kernel properly blocks it, it returns an error (EPERM, ENOTTY, or EIO).
func CheckTIOCSTI(f *os.File) error {
	if f == nil {
		return errors.New("file descriptor is nil")
	}

	char := byte('\n')
	req := TIOCSTIRequest(runtime.GOOS)
	// We test standard TIOCSTI ioctl
	_, _, err := syscall.Syscall(
		syscall.SYS_IOCTL,
		f.Fd(),
		req,
		uintptr(unsafe.Pointer(&char)),
	)
	if err != 0 {
		return err
	}
	return nil
}
