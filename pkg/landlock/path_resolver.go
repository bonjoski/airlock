package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrSymlinkTraversal indicates an insecure symlink or TOCTOU replacement attack was detected.
	ErrSymlinkTraversal = errors.New("landlock: insecure symlink detected during path resolution")
	// ErrDeniedPathTarget indicates a rule targets or resolves into a forbidden deny path.
	ErrDeniedPathTarget = errors.New("landlock: path resolves to forbidden deny path")
)

// IsDeniedPath returns true if targetPath matches or resides beneath any forbidden deny path.
func IsDeniedPath(targetPath string, denyPaths []string) bool {
	if targetPath == "" || len(denyPaths) == 0 {
		return false
	}

	targetClean := filepath.Clean(targetPath)
	var homeDir string
	if home, err := os.UserHomeDir(); err == nil {
		homeDir = home
	}

	for _, deny := range denyPaths {
		deny = strings.TrimSpace(deny)
		if deny == "" {
			continue
		}

		// Expand ~/
		expandedDeny := deny
		if homeDir != "" && (deny == "~" || strings.HasPrefix(deny, "~/")) {
			expandedDeny = filepath.Join(homeDir, strings.TrimPrefix(deny, "~/"))
		}

		denyClean := filepath.Clean(expandedDeny)
		if targetClean == denyClean {
			return true
		}

		// Check if targetClean is a descendant of denyClean
		prefix := denyClean + string(filepath.Separator)
		if strings.HasPrefix(targetClean, prefix) {
			return true
		}

		// Check filename pattern matching (e.g. .env, .env.*)
		base := filepath.Base(targetClean)
		if matched, _ := filepath.Match(deny, base); matched {
			return true
		}

		// If pattern starts with '.', check if any path segment matches
		if strings.HasPrefix(deny, ".") {
			parts := strings.Split(targetClean, string(filepath.Separator))
			for _, part := range parts {
				if matched, _ := filepath.Match(deny, part); matched {
					return true
				}
			}
		}
	}

	return false
}

// IsEscapingWorkspace checks if resolved target escapes workspace root.
func IsEscapingWorkspace(target, workspaceRoot string) bool {
	if workspaceRoot == "" || target == "" {
		return false
	}
	wsClean := filepath.Clean(workspaceRoot)
	targetClean := filepath.Clean(target)
	if targetClean == wsClean {
		return false
	}
	prefix := wsClean + string(filepath.Separator)
	return !strings.HasPrefix(targetClean, prefix)
}
