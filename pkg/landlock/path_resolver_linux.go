//go:build linux

package landlock

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"golang.org/x/sys/unix"
)

// SafePinPathFD securely resolves and pins a filesystem path to an open file descriptor.
// It uses unix.O_PATH | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NOFOLLOW to guard against
// TOCTOU symlink replacement attacks during rapid workspace setup.
// If the path is a file or socket, it falls back to non-O_DIRECTORY.
// It verifies that the pinned file descriptor does not resolve to any forbidden deny path via /proc/self/fd/<fd>.
func SafePinPathFD(path string, denyPaths []string, workspaceRoot string) (int, error) {
	cleanPath := filepath.Clean(path)
	if IsDeniedPath(cleanPath, denyPaths) {
		return -1, fmt.Errorf("%w: %s matches deny policy", ErrDeniedPathTarget, cleanPath)
	}

	const oPath = 0x200000 // unix.O_PATH
	// 1. Attempt opening as a directory with O_DIRECTORY | O_NOFOLLOW
	flags := oPath | syscall.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
	fd, err := unix.Open(cleanPath, flags, 0)
	if err != nil {
		if errors.Is(err, unix.ENOTDIR) {
			// Not a directory: try regular file/socket with O_NOFOLLOW
			flags = oPath | syscall.O_CLOEXEC | unix.O_NOFOLLOW
			fd, err = unix.Open(cleanPath, flags, 0)
		}
	}

	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			// A symlink was encountered at the target path.
			// Evaluate where the symlink points
			resolved, evalErr := filepath.EvalSymlinks(cleanPath)
			if evalErr != nil {
				return -1, fmt.Errorf("%w: failed to evaluate symlink %s: %w", ErrSymlinkTraversal, cleanPath, evalErr)
			}

			// If the path was inside the workspace but resolves outside workspace, reject it!
			if workspaceRoot != "" && strings.HasPrefix(cleanPath, filepath.Clean(workspaceRoot)) {
				if IsEscapingWorkspace(resolved, workspaceRoot) {
					return -1, fmt.Errorf("%w: workspace symlink %s escapes workspace root %s -> %s", ErrSymlinkTraversal, cleanPath, workspaceRoot, resolved)
				}
			}

			// Reject if it resolves to any deny path
			if IsDeniedPath(resolved, denyPaths) {
				return -1, fmt.Errorf("%w: symlink %s resolves to denied path %s", ErrDeniedPathTarget, cleanPath, resolved)
			}

			// Pin the resolved canonical path with O_NOFOLLOW
			fd, err = unix.Open(resolved, oPath|syscall.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
			if err != nil && errors.Is(err, unix.ENOTDIR) {
				fd, err = unix.Open(resolved, oPath|syscall.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			}
			if err != nil {
				if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
					return -1, fmt.Errorf("%w: symlink race condition on %s: %w", ErrSymlinkTraversal, cleanPath, err)
				}
				return -1, err
			}
		} else {
			return -1, err
		}
	}

	// 2. Defense-in-depth: verify the pinned file descriptor's real path via /proc/self/fd/<fd>
	procPath := fmt.Sprintf("/proc/self/fd/%d", fd)
	realPath, err := os.Readlink(procPath)
	if err == nil && realPath != "" {
		if IsDeniedPath(realPath, denyPaths) {
			_ = unix.Close(fd)
			return -1, fmt.Errorf("%w: pinned fd for %s points to denied path %s", ErrDeniedPathTarget, cleanPath, realPath)
		}
		if workspaceRoot != "" && strings.HasPrefix(cleanPath, filepath.Clean(workspaceRoot)) {
			if IsEscapingWorkspace(realPath, workspaceRoot) {
				_ = unix.Close(fd)
				return -1, fmt.Errorf("%w: pinned fd for workspace path %s escapes to %s", ErrSymlinkTraversal, cleanPath, realPath)
			}
		}
	}

	return fd, nil
}
