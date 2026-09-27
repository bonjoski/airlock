package sandbox

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/cache"
	"github.com/bonjoski/airlock/pkg/scratch"
	"github.com/bonjoski/airlock/pkg/seccomp"
)

func TestFindWorkspaceSecrets(t *testing.T) {
	tempDir := t.TempDir()

	secretFiles := []string{
		".env",
		".env.local",
		".env.production",
		"id_rsa",
		"id_ed25519",
		"server.pem",
		"secrets.json",
		"service-account.json",
	}

	for _, name := range secretFiles {
		p := filepath.Join(tempDir, name)
		if err := os.WriteFile(p, []byte("SECRET"), 0600); err != nil {
			t.Fatalf("WriteFile %s failed: %v", name, err)
		}
	}

	// Normal non-secret files
	normalFiles := []string{"main.go", "package.json", "README.md"}
	for _, name := range normalFiles {
		p := filepath.Join(tempDir, name)
		if err := os.WriteFile(p, []byte("CODE"), 0644); err != nil {
			t.Fatalf("WriteFile %s failed: %v", name, err)
		}
	}

	found, err := FindWorkspaceSecrets(tempDir)
	if err != nil {
		t.Fatalf("FindWorkspaceSecrets failed: %v", err)
	}

	if len(found) != len(secretFiles) {
		t.Errorf("Expected %d secrets, got %d: %v", len(secretFiles), len(found), found)
	}

	for _, sec := range found {
		base := filepath.Base(sec)
		isSecret := false
		for _, expected := range secretFiles {
			if base == expected {
				isSecret = true
				break
			}
		}
		if !isSecret {
			t.Errorf("Non-secret file returned as secret: %s", base)
		}
	}
}

func TestLinuxEngine_BuildBwrapArgs(t *testing.T) {
	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	if err := os.Mkdir(workspace, 0755); err != nil {
		t.Fatalf("Mkdir workspace failed: %v", err)
	}

	// Create .git directory
	gitDir := filepath.Join(workspace, ".git")
	if err := os.Mkdir(gitDir, 0755); err != nil {
		t.Fatalf("Mkdir .git failed: %v", err)
	}

	// Create a .env file to verify secret masking
	envFile := filepath.Join(workspace, ".env")
	if err := os.WriteFile(envFile, []byte("SECRET=1"), 0600); err != nil {
		t.Fatalf("WriteFile .env failed: %v", err)
	}

	sc, err := scratch.New(tempDir)
	if err != nil {
		t.Fatalf("scratch.New failed: %v", err)
	}
	defer func() {
		_ = sc.Cleanup()
	}()

	filter := seccomp.NewFilter()
	seccompFile, err := filter.CreateFilterFile("amd64")
	if err != nil {
		t.Fatalf("CreateFilterFile failed: %v", err)
	}
	defer func() {
		_ = seccompFile.Close()
		_ = os.Remove(seccompFile.Name())
	}()

	opts := Options{
		WorkspaceRoot:  workspace,
		Airgap:         false,
		AllowDirectNet: false,
	}

	eng := &LinuxEngine{
		opts:      opts,
		bwrapPath: "/usr/bin/bwrap",
		seccomp:   filter,
		cacheMgr:  cache.NewManager(),
	}

	mockHome := filepath.Join(tempDir, "home")
	args, err := eng.BuildBwrapArgs(sc, seccompFile, mockHome)
	if err != nil {
		t.Fatalf("BuildBwrapArgs failed: %v", err)
	}

	argsStr := strings.Join(args, " ")

	// 1. Mandatory namespace isolation
	if !strings.Contains(argsStr, "--unshare-user") ||
		!strings.Contains(argsStr, "--unshare-pid") ||
		!strings.Contains(argsStr, "--unshare-ipc") {
		t.Errorf("Missing namespace isolation flags: %s", argsStr)
	}

	// 2. Mandatory network isolation (V-09)
	if !strings.Contains(argsStr, "--unshare-net") {
		t.Errorf("Missing --unshare-net flag in proxy/airgap mode")
	}

	// 3. Git protection (V-03)
	if !strings.Contains(argsStr, "--ro-bind-try "+gitDir+" "+gitDir) {
		t.Errorf("Missing read-only .git mount: %s", argsStr)
	}

	// 4. Secret masking (V-04)
	if !strings.Contains(argsStr, "--ro-bind") || !strings.Contains(argsStr, envFile) {
		t.Errorf("Missing workspace secret masking mount for %s: %s", envFile, argsStr)
	}

	// 5. Seccomp filter attachment (Target 2)
	if !strings.Contains(argsStr, "--seccomp 3") {
		t.Errorf("Missing --seccomp 3 flag: %s", argsStr)
	}

	// 6. Die with parent and separator
	if !strings.Contains(argsStr, "--die-with-parent --") {
		t.Errorf("Missing --die-with-parent -- terminator: %s", argsStr)
	}
}

func TestLinuxEngine_NestedBypass(t *testing.T) {
	origVal := os.Getenv("__AIRLOCK_ACTIVE")
	_ = os.Setenv("__AIRLOCK_ACTIVE", "1")
	defer func() {
		_ = os.Setenv("__AIRLOCK_ACTIVE", origVal)
	}()

	tempDir := t.TempDir()
	opts := Options{
		WorkspaceRoot: tempDir,
	}

	eng := &LinuxEngine{
		opts:      opts,
		bwrapPath: "/nonexistent/bwrap", // would fail if executed
	}

	// Should execute directly via exec.Command without touching bwrapPath
	code, err := eng.Execute(context.Background(), []string{"/bin/sh", "-c", "exit 0"})
	if err != nil {
		t.Fatalf("Nested execution failed: %v", err)
	}
	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}
}
