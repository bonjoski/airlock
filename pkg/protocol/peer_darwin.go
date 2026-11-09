//go:build darwin

package protocol

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/unix"
)

const (
	procInfoCallPidInfo    = 2
	procPidPathInfo        = 11
	procPidPathInfoMaxSize = 4096
)

// GetProcessStartTime queries Darwin kernel process start time in nanoseconds via sysctl.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("peer: invalid pid %d", pid)
	}

	kp, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return 0, fmt.Errorf("peer: failed to inspect pid %d start time: %w", pid, err)
	}
	if kp == nil {
		return 0, fmt.Errorf("peer: process %d not found", pid)
	}

	return kp.Proc.P_starttime.Nano(), nil
}

// GetProcessExecutablePath queries the kernel vnode binary path for a given pid via proc_pidpath.
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("peer: invalid pid %d", pid)
	}

	buf := make([]byte, procPidPathInfoMaxSize)
	ret, _, errno := unix.Syscall6(
		unix.SYS_PROC_INFO,
		procInfoCallPidInfo,
		uintptr(pid),
		procPidPathInfo,
		0,
		uintptr(unsafe.Pointer(&buf[0])),
		uintptr(len(buf)),
	)
	if errno != 0 {
		return "", fmt.Errorf("peer: failed to get executable path for pid %d: %w", pid, errno)
	}

	slice := buf
	if ret > 0 && int(ret) <= len(buf) {
		slice = buf[:int(ret)]
	}
	exePath := unix.ByteSliceToString(slice)
	if exePath == "" {
		return "", fmt.Errorf("peer: empty executable path for pid %d", pid)
	}
	return exePath, nil
}
