package cache

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

func TestManager_GetHostCacheMounts(t *testing.T) {
	mgr := NewManager()
	userHome := "/Users/testuser"

	mounts := mgr.GetHostCacheMounts(userHome)
	if len(mounts) == 0 {
		t.Fatal("Expected mounts to be non-empty")
	}

	foundNpm := false
	foundPip := false
	foundUv := false

	for _, m := range mounts {
		if !m.ReadOnly {
			t.Errorf("Expected mount %s to be ReadOnly", m.HostPath)
		}
		if m.HostPath == filepath.Join(userHome, ".npm") {
			foundNpm = true
		}
		if m.HostPath == filepath.Join(userHome, ".cache", "pip") {
			foundPip = true
		}
		if m.HostPath == filepath.Join(userHome, ".cache", "uv") {
			foundUv = true
		}
	}

	if !foundNpm || !foundPip || !foundUv {
		t.Errorf("Missing expected package manager mount: npm=%v, pip=%v, uv=%v", foundNpm, foundPip, foundUv)
	}
}

func TestManager_ProvisionStaging(t *testing.T) {
	tempDir := t.TempDir()
	stagingBase := filepath.Join(tempDir, "cache-staging")

	mgr := NewManager()
	cfg, err := mgr.ProvisionStaging(stagingBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	if cfg.BaseDir != stagingBase {
		t.Errorf("Expected BaseDir %s, got %s", stagingBase, cfg.BaseDir)
	}

	// Verify directories were created
	for _, sub := range []string{"npm", "pip", "uv", "yarn"} {
		path := filepath.Join(stagingBase, sub)
		info, err := os.Stat(path)
		if err != nil {
			t.Errorf("Subdirectory %s was not created: %v", sub, err)
			continue
		}
		if !info.IsDir() {
			t.Errorf("Path %s is not a directory", path)
		}
	}

	// Verify env vars
	if cfg.EnvVars["npm_config_cache"] != filepath.Join(stagingBase, "npm") {
		t.Errorf("npm_config_cache mismatch: %s", cfg.EnvVars["npm_config_cache"])
	}
	if cfg.EnvVars["PIP_CACHE_DIR"] != filepath.Join(stagingBase, "pip") {
		t.Errorf("PIP_CACHE_DIR mismatch: %s", cfg.EnvVars["PIP_CACHE_DIR"])
	}
	if cfg.EnvVars["UV_CACHE_DIR"] != filepath.Join(stagingBase, "uv") {
		t.Errorf("UV_CACHE_DIR mismatch: %s", cfg.EnvVars["UV_CACHE_DIR"])
	}
}

func TestManager_SyncBack_Valid(t *testing.T) {
	tempDir := t.TempDir()
	stagingBase := filepath.Join(tempDir, "staging")
	mockHome := filepath.Join(tempDir, "home")

	mgr := NewManager()
	_, err := mgr.ProvisionStaging(stagingBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	// Simulate npm downloading a package tarball
	npmStagingPkg := filepath.Join(stagingBase, "npm", "_cacache", "content-v2", "ab", "cd")
	if err := os.MkdirAll(npmStagingPkg, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}
	samplePayload := []byte("PACKAGED_NPM_TARBALL_DATA")
	sampleFile := filepath.Join(npmStagingPkg, "123456789")
	if err := os.WriteFile(sampleFile, samplePayload, 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Run SyncBack
	if err := mgr.SyncBack(stagingBase, mockHome); err != nil {
		t.Fatalf("SyncBack failed: %v", err)
	}

	// Verify file was copied to host cache
	expectedHostFile := filepath.Join(mockHome, ".npm", "_cacache", "content-v2", "ab", "cd", "123456789")
	data, err := os.ReadFile(expectedHostFile)
	if err != nil {
		t.Fatalf("Failed to read synced file on host: %v", err)
	}
	if string(data) != string(samplePayload) {
		t.Errorf("Synced file content mismatch. Got %s, expected %s", string(data), string(samplePayload))
	}
}

func TestManager_SyncBack_SymlinkRejection(t *testing.T) {
	tempDir := t.TempDir()
	stagingBase := filepath.Join(tempDir, "staging")
	mockHome := filepath.Join(tempDir, "home")

	mgr := NewManager()
	_, err := mgr.ProvisionStaging(stagingBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	// Plant a malicious symlink pointing to an arbitrary location
	trojanTarget := filepath.Join(tempDir, "victim.txt")
	_ = os.WriteFile(trojanTarget, []byte("sensitive"), 0600)

	symlinkPath := filepath.Join(stagingBase, "npm", "malicious_link")
	if err := os.Symlink(trojanTarget, symlinkPath); err != nil {
		t.Fatalf("Failed to create symlink: %v", err)
	}

	// SyncBack should detect symlink and abort
	err = mgr.SyncBack(stagingBase, mockHome)
	if err == nil {
		t.Fatal("Expected SyncBack to fail due to symlink, got nil")
	}

	if !errors.Is(err, ErrSymlinkRejected) {
		t.Errorf("Expected ErrSymlinkRejected, got: %v", err)
	}
}

func TestManager_SyncBack_Empty(t *testing.T) {
	tempDir := t.TempDir()
	stagingBase := filepath.Join(tempDir, "staging")
	mockHome := filepath.Join(tempDir, "home")

	mgr := NewManager()
	_, err := mgr.ProvisionStaging(stagingBase)
	if err != nil {
		t.Fatalf("ProvisionStaging failed: %v", err)
	}

	// Empty sync should succeed without errors
	if err := mgr.SyncBack(stagingBase, mockHome); err != nil {
		t.Fatalf("Empty SyncBack returned error: %v", err)
	}
}
