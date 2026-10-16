//go:build !darwin && !linux

package protocol

import (
	"errors"
	"os"
)

// GetProcessStartTime fallback
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, errors.New("peer: invalid pid")
	}
	return 1, nil
}

// GetProcessExecutablePath fallback
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", errors.New("peer: invalid pid")
	}
	return os.Executable()
}
