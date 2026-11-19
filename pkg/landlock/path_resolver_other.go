//go:build !linux && !darwin

package landlock

import (
	"errors"
)

// SafePinPathFD is a stub for platforms without Unix file descriptor pinning support.
func SafePinPathFD(path string, denyPaths []string, workspaceRoot string) (int, error) {
	return -1, errors.New("safe fd pinning not supported on this platform")
}
