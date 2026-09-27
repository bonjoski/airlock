package shim

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

func TestShimManager_Lifecycle(t *testing.T) {
	tempDir := t.TempDir()
	shimDir := filepath.Join(tempDir, "bin")

	mgr := NewManager()

	// 1. Install
	installed, err := mgr.Install(shimDir)
	if err != nil {
		t.Fatalf("Install failed: %v", err)
	}

	if len(installed) != len(SupportedTools) {
		t.Errorf("Expected %d installed shims, got %d", len(SupportedTools), len(installed))
	}

	for _, p := range installed {
		info, err := os.Stat(p)
		if err != nil {
			t.Errorf("Failed to stat installed shim %s: %v", p, err)
			continue
		}
		if info.Mode()&0111 == 0 {
			t.Errorf("Shim %s is not executable: mode %v", p, info.Mode())
		}
		content, err := os.ReadFile(p)
		if err != nil {
			t.Errorf("Failed to read %s: %v", p, err)
			continue
		}
		if !strings.Contains(string(content), "__AIRLOCK_ACTIVE") {
			t.Errorf("Shim %s missing __AIRLOCK_ACTIVE check", p)
		}
	}

	// 2. List
	statuses, err := mgr.List(shimDir)
	if err != nil {
		t.Fatalf("List failed: %v", err)
	}
	if len(statuses) != len(SupportedTools) {
		t.Errorf("Expected %d statuses, got %d", len(SupportedTools), len(statuses))
	}
	for _, s := range statuses {
		if !s.Installed {
			t.Errorf("Expected tool %s to be reported as installed", s.Tool)
		}
	}

	// 3. Uninstall
	if err := mgr.Uninstall(shimDir); err != nil {
		t.Fatalf("Uninstall failed: %v", err)
	}

	statusesAfter, err := mgr.List(shimDir)
	if err != nil {
		t.Fatalf("List after uninstall failed: %v", err)
	}
	for _, s := range statusesAfter {
		if s.Installed {
			t.Errorf("Expected tool %s to NOT be installed after uninstall", s.Tool)
		}
	}
}

func TestShim_RecursionBypassExecution(t *testing.T) {
	tempDir := t.TempDir()
	shimDir := filepath.Join(tempDir, "shim-bin")
	realBinDir := filepath.Join(tempDir, "real-bin")

	_ = os.MkdirAll(shimDir, 0755)
	_ = os.MkdirAll(realBinDir, 0755)

	// Create a mock "npm" real binary in realBinDir
	realNpm := filepath.Join(realBinDir, "npm")
	realContent := "#!/bin/sh\necho \"REAL_NPM_CALLED:$@\"\n"
	if err := os.WriteFile(realNpm, []byte(realContent), 0755); err != nil {
		t.Fatalf("Failed to write real npm: %v", err)
	}

	// Generate and install the shim in shimDir
	shimNpm := filepath.Join(shimDir, "npm")
	if err := os.WriteFile(shimNpm, []byte(generateShimScript("npm")), 0755); err != nil {
		t.Fatalf("Failed to write shim npm: %v", err)
	}

	// Setup PATH with shimDir FIRST, realBinDir SECOND, and system utilities
	customPath := shimDir + string(os.PathListSeparator) + realBinDir + string(os.PathListSeparator) + "/bin" + string(os.PathListSeparator) + "/usr/bin"

	// Execute the shim with __AIRLOCK_ACTIVE=1
	cmd := exec.Command("/bin/sh", shimNpm, "test-arg-1", "test-arg-2")
	cmd.Env = []string{
		"PATH=" + customPath,
		"__AIRLOCK_ACTIVE=1",
	}

	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("Shim execution failed: %v, output: %s", err, string(out))
	}

	if !strings.Contains(string(out), "REAL_NPM_CALLED:test-arg-1 test-arg-2") {
		t.Errorf("Expected real npm to be executed avoiding recursion, got: %s", string(out))
	}
}
