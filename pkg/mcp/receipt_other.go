//go:build !unix

package mcp

import (
	"fmt"
	"os"
)

func verifyDirNoFollow(dir string) error {
	fi, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("receipt directory %q stat failed: %w", dir, err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("receipt directory %q must not be a symlink", dir)
	}
	if !fi.IsDir() {
		return fmt.Errorf("receipt directory %q is not a directory", dir)
	}
	return nil
}
