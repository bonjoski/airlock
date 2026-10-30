//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"os"
	"syscall"
	"unsafe"
)

// IsSupported checks if the host kernel supports Landlock LSM.
func IsSupported() bool {
	// landlock_create_ruleset(NULL, 0, LANDLOCK_CREATE_RULESET_VERSION) returns abi version >= 1
	r1, _, err := syscall.Syscall(
		SysLandlockCreateRuleset,
		0,
		0,
		uintptr(CreateRulesetVersion),
	)
	if err != 0 && !errors.Is(err, syscall.Errno(0)) {
		return false
	}
	return int(r1) >= 1
}

// Apply restricts the current process using the synthesized Landlock ruleset.
func Apply(rs *Ruleset) error {
	if rs == nil || rs.HandledAccessFS == 0 {
		return errors.New("landlock: empty ruleset")
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

	// 2. Create ruleset
	attr := RulesetAttr{
		HandledAccessFS: rs.HandledAccessFS,
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

	// 3. Populate path rules
	for _, rule := range rs.Rules {
		if _, statErr := os.Stat(rule.Path); statErr != nil {
			// Path does not exist on host; safely skip
			continue
		}

		// Open target directory/file with O_PATH | O_CLOEXEC
		const oPath = 0x200000
		fd, openErr := syscall.Open(rule.Path, oPath|syscall.O_CLOEXEC, 0)
		if openErr != nil {
			continue
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
		_ = syscall.Close(fd)

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
