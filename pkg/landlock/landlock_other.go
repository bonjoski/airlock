//go:build !linux

package landlock

import (
	"fmt"
	"runtime"
)

// GetABIVersion returns 0 on non-Linux platforms.
func GetABIVersion() int {
	return 0
}

// IsSupported checks if the host kernel supports Landlock LSM.
func IsSupported() bool {
	return false
}

// Apply restricts the current process using the synthesized Landlock ruleset.
func Apply(rs *Ruleset) error {
	return fmt.Errorf("%w: not available on %s", ErrLandlockNotSupported, runtime.GOOS)
}
