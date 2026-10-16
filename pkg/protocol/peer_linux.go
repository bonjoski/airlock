//go:build linux

package protocol

import (
	"fmt"
	"os"
	"strconv"
	"strings"
)

// GetProcessStartTime extracts field 22 from /proc/<pid>/stat.
func GetProcessStartTime(pid int) (int64, error) {
	if pid <= 0 {
		return 0, fmt.Errorf("peer: invalid pid %d", pid)
	}

	data, err := os.ReadFile(fmt.Sprintf("/proc/%d/stat", pid))
	if err != nil {
		return 0, fmt.Errorf("peer: failed to read /proc/%d/stat: %w", pid, err)
	}

	content := string(data)
	closeIdx := strings.LastIndex(content, ")")
	if closeIdx == -1 || closeIdx+2 >= len(content) {
		return 0, fmt.Errorf("peer: malformed /proc/%d/stat", pid)
	}

	fields := strings.Fields(content[closeIdx+2:])
	if len(fields) < 20 {
		return 0, fmt.Errorf("peer: insufficient fields in /proc/%d/stat", pid)
	}

	startTime, err := strconv.ParseInt(fields[19], 10, 64)
	if err != nil {
		return 0, fmt.Errorf("peer: failed to parse starttime for pid %d: %w", pid, err)
	}

	return startTime, nil
}

// GetProcessExecutablePath reads /proc/<pid>/exe symlink.
func GetProcessExecutablePath(pid int) (string, error) {
	if pid <= 0 {
		return "", fmt.Errorf("peer: invalid pid %d", pid)
	}
	return os.Readlink(fmt.Sprintf("/proc/%d/exe", pid))
}
