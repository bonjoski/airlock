//go:build darwin

package sandbox

import "os/exec"

// isKernelSandboxed verifies whether the current process is genuinely confined
// inside an active macOS Seatbelt kernel sandbox (AIR-03).
// On XNU, calling sandbox_apply inside an already-sandboxed process fails with EPERM (exit 71),
// whereas a spoofed __AIRLOCK_ACTIVE=1 on an unconfined host allows sandbox-exec to succeed.
func isKernelSandboxed() bool {
	cmd := exec.Command("sandbox-exec", "-p", "(version 1)(allow default)", "/usr/bin/true")
	return cmd.Run() != nil
}
