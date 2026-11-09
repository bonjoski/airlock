//go:build linux

package sandbox

import "golang.org/x/sys/unix"

// isKernelSandboxed verifies whether the current process has an active kernel
// Seccomp filter attached via PR_GET_SECCOMP (AIR-03).
func isKernelSandboxed() bool {
	mode, err := unix.PrctlRetInt(unix.PR_GET_SECCOMP, 0, 0, 0, 0)
	return err == nil && mode > 0
}
