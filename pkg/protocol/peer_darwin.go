//go:build darwin

package protocol

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"
)

// GetProcessStartTime queries Darwin process start time.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("peer: invalid pid %d", pid)
	}

	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "lstart=").Output()
	if err != nil {
		return 0, fmt.Errorf("peer: failed to inspect pid %d start time: %w", pid, err)
	}

	cleanStr := strings.TrimSpace(string(out))
	if cleanStr == "" {
		return 0, fmt.Errorf("peer: empty start time for pid %d", pid)
	}
	return int64(len(cleanStr)), nil
}

// GetProcessExecutablePath queries binary path for a given pid.
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("peer: invalid pid %d", pid)
	}

	out, err := exec.Command("ps", "-p", strconv.Itoa(pid), "-o", "comm=").Output()
	if err != nil {
		return "", fmt.Errorf("peer: failed to get executable path for pid %d: %w", pid, err)
	}

	exePath := strings.TrimSpace(string(out))
	if exePath == "" {
		return "", fmt.Errorf("peer: empty executable path for pid %d", pid)
	}
	return exePath, nil
}
