//go:build unix

package mcp

import (
	"fmt"
	"os"
	"syscall"
)

// verifyDirNoFollow opens dir with O_RDONLY|O_DIRECTORY|O_NOFOLLOW to reject symlinks
// atomically without TOCTOU, and verifies ownership by the current user.
func verifyDirNoFollow(dir string) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return fmt.Errorf("receipt directory %q failed O_NOFOLLOW verification: %w", dir, err)
	}
	defer syscall.Close(fd)

	var st syscall.Stat_t
	if err := syscall.Fstat(fd, &st); err != nil {
		return fmt.Errorf("failed to stat receipt directory %q: %w", dir, err)
	}
	if int(st.Uid) != os.Getuid() {
		return fmt.Errorf("receipt directory %q owner UID %d does not match current UID %d", dir, st.Uid, os.Getuid())
	}
	return nil
}
