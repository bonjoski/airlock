//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// GetABIVersion returns the Landlock ABI version supported by the kernel, or 0 if unsupported.
func GetABIVersion() int {
	r1, _, err := syscall.Syscall(
		SysLandlockCreateRuleset,
		0,
		0,
		uintptr(CreateRulesetVersion),
	)
	if err != 0 && !errors.Is(err, syscall.Errno(0)) {
		return 0
	}
	return int(r1)
}

// IsSupported checks if the host kernel supports Landlock LSM.
func IsSupported() bool {
	return GetABIVersion() >= 1
}

// Apply restricts the current process using the synthesized Landlock ruleset.
func Apply(rs *Ruleset) error {
	if rs == nil || rs.HandledAccessFS == 0 {
		return errors.New("landlock: empty ruleset")
	}

	abi := GetABIVersion()
	if abi <= 0 {
		return ErrLandlockNotSupported
	}

	// 1. Enforce PR_SET_NO_NEW_PRIVS (required before restrict_self)
	const prSetNoNewPrivs = 38
	r, _, err := syscall.Syscall6(
		syscall.SYS_PRCTL,
		uintptr(prSetNoNewPrivs),
		1,
		0,
		0,
		0,
		0,
	)
	if err != 0 && r != 0 {
		return fmt.Errorf("landlock: failed to set PR_SET_NO_NEW_PRIVS: %w", err)
	}

	// 2. Create ruleset with flags safely masked to the kernel's supported ABI level
	attr := RulesetAttr{
		HandledAccessFS: MaskSupportedAccessFS(rs.HandledAccessFS, abi),
	}
	rulesetFD, _, err := syscall.Syscall(
		SysLandlockCreateRuleset,
		uintptr(unsafe.Pointer(&attr)),
		unsafe.Sizeof(attr),
		0,
	)
	if err != 0 {
		return fmt.Errorf("landlock: landlock_create_ruleset failed: %w", err)
	}
	defer syscall.Close(int(rulesetFD))

	// 3. Populate path rules using pinned file descriptors (O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW)
	for _, rule := range rs.Rules {
		fd, err := SafePinPathFD(rule.Path, rs.DenyPaths, rs.WorkspaceRoot)
		if err != nil {
			if errors.Is(err, unix.ENOENT) {
				// Path does not exist on host; safely skip (e.g. optional toolchains)
				continue
			}
			// Security-critical: symlink replacement attacks or deny path violations fail closed
			return fmt.Errorf("landlock: failed to safely pin rule path %s: %w", rule.Path, err)
		}

		pbAttr := PathBeneathAttr{
			AllowedAccess: rule.Access & rs.HandledAccessFS,
			ParentFD:      int32(fd),
		}

		_, _, addErr := syscall.Syscall(
			SysLandlockAddRule,
			rulesetFD,
			uintptr(RuleTypePathBeneath),
			uintptr(unsafe.Pointer(&pbAttr)),
		)
		_ = unix.Close(fd)

		if addErr != 0 {
			return fmt.Errorf("landlock: failed to add rule for %s: %w", rule.Path, addErr)
		}
	}

	// 4. Restrict self
	_, _, restrErr := syscall.Syscall(
		SysLandlockRestrictSelf,
		rulesetFD,
		0,
		0,
	)
	if restrErr != 0 {
		return fmt.Errorf("landlock: landlock_restrict_self failed: %w", restrErr)
	}

	return nil
}
