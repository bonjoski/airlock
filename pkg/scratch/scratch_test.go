package scratch

import (
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestDefaultManager_Lifecycle(t *testing.T) {
	tempBase := t.TempDir()

	mgr, err := New(tempBase)
	if err != nil {
		t.Fatalf("Failed to create scratch manager: %v", err)
	}

	// Verify permissions are 0700
	info, err := os.Stat(mgr.Root())
	if err != nil {
		t.Fatalf("Failed to stat scratch root: %v", err)
	}
	if !IsPrivatePermissions(info.Mode()) {
		t.Errorf("Expected private permissions (0700 on POSIX), got %#o", info.Mode().Perm())
	}

	// Verify subdirectories
	for _, sub := range []string{mgr.TmpDir(), mgr.HomeDir(), mgr.CacheStagingDir()} {
		subInfo, err := os.Stat(sub)
		if err != nil || !subInfo.IsDir() {
			t.Errorf("Subdirectory %s missing or invalid", sub)
		}
	}

	// Verify cleanup
	rootPath := mgr.Root()
	if err := mgr.Cleanup(); err != nil {
		t.Errorf("Cleanup failed: %v", err)
	}

	if _, err := os.Stat(rootPath); !os.IsNotExist(err) {
		t.Errorf("Expected root path to be removed after Cleanup")
	}
}

func TestScavengeOrphans(t *testing.T) {
	tempBase := t.TempDir()

	// Old orphan (>48h)
	oldOrphan := filepath.Join(tempBase, "boxpkg-old0123456789")
	if err := os.Mkdir(oldOrphan, 0700); err != nil {
		t.Fatalf("Failed to create old orphan: %v", err)
	}
	oldTime := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(oldOrphan, oldTime, oldTime)

	// Fresh dir (<1h)
	freshDir := filepath.Join(tempBase, "boxpkg-fresh987654321")
	if err := os.Mkdir(freshDir, 0700); err != nil {
		t.Fatalf("Failed to create fresh dir: %v", err)
	}

	// Non-boxpkg dir
	otherDir := filepath.Join(tempBase, "other-data")
	if err := os.Mkdir(otherDir, 0700); err != nil {
		t.Fatalf("Failed to create other dir: %v", err)
	}
	_ = os.Chtimes(otherDir, oldTime, oldTime)

	cleaned, err := ScavengeOrphans(tempBase, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScavengeOrphans failed: %v", err)
	}

	if cleaned != 1 {
		t.Errorf("Expected 1 orphan cleaned, got %d", cleaned)
	}

	if _, err := os.Stat(oldOrphan); !os.IsNotExist(err) {
		t.Errorf("Expected old orphan to be deleted")
	}
	if _, err := os.Stat(freshDir); err != nil {
		t.Errorf("Expected fresh dir to remain intact")
	}
	if _, err := os.Stat(otherDir); err != nil {
		t.Errorf("Expected other dir to remain intact")
	}
}
