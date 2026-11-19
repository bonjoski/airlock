//go:build darwin

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

// SafePinPathFD securely resolves and pins a filesystem path on macOS.
// It uses unix.O_RDONLY | unix.O_CLOEXEC | unix.O_DIRECTORY | unix.O_NOFOLLOW to pin directories
// and guard against symlink replacement attacks.
func SafePinPathFD(path string, denyPaths []string, workspaceRoot string) (int, error) {
	cleanPath := filepath.Clean(path)
	if IsDeniedPath(cleanPath, denyPaths) {
		return -1, fmt.Errorf("%w: %s matches deny policy", ErrDeniedPathTarget, cleanPath)
	}

	// 1. Attempt opening as directory with O_DIRECTORY | O_NOFOLLOW
	flags := syscall.O_RDONLY | syscall.O_CLOEXEC | unix.O_NOFOLLOW | unix.O_DIRECTORY
	fd, err := unix.Open(cleanPath, flags, 0)
	if err != nil {
		if errors.Is(err, unix.ENOTDIR) {
			// Check if cleanPath is a symlink
			if fi, lerr := os.Lstat(cleanPath); lerr == nil && fi.Mode()&os.ModeSymlink != 0 {
				err = unix.ELOOP
			} else {
				// Not a symlink, open as regular file
				flags = syscall.O_RDONLY | syscall.O_CLOEXEC | unix.O_NOFOLLOW
				fd, err = unix.Open(cleanPath, flags, 0)
			}
		}
	}

	if err != nil {
		if errors.Is(err, unix.ELOOP) || errors.Is(err, unix.EMLINK) {
			resolved, evalErr := filepath.EvalSymlinks(cleanPath)
			if evalErr != nil {
				return -1, fmt.Errorf("%w: failed to evaluate symlink %s: %w", ErrSymlinkTraversal, cleanPath, evalErr)
			}

			if workspaceRoot != "" && strings.HasPrefix(cleanPath, filepath.Clean(workspaceRoot)) {
				if IsEscapingWorkspace(resolved, workspaceRoot) {
					return -1, fmt.Errorf("%w: workspace symlink %s escapes workspace root %s -> %s", ErrSymlinkTraversal, cleanPath, workspaceRoot, resolved)
				}
			}

			if IsDeniedPath(resolved, denyPaths) {
				return -1, fmt.Errorf("%w: symlink %s resolves to denied path %s", ErrDeniedPathTarget, cleanPath, resolved)
			}

			fd, err = unix.Open(resolved, syscall.O_RDONLY|syscall.O_CLOEXEC|unix.O_NOFOLLOW|unix.O_DIRECTORY, 0)
			if err != nil && errors.Is(err, unix.ENOTDIR) {
				fd, err = unix.Open(resolved, syscall.O_RDONLY|syscall.O_CLOEXEC|unix.O_NOFOLLOW, 0)
			}
			if err != nil {
				return -1, fmt.Errorf("%w: symlink race condition on %s: %w", ErrSymlinkTraversal, cleanPath, err)
			}
		} else {
			return -1, err
		}
	}

	return fd, nil
}
