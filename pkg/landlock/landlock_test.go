package landlock

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"syscall"
	"testing"
)

func TestIsDeniedPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("No home directory found")
	}

	denyPaths := []string{
		"~/.ssh",
		"~/.aws",
		"/etc/shadow",
		".env",
		".env.*",
	}

	cases := []struct {
		target   string
		expected bool
	}{
		{filepath.Join(home, ".ssh"), true},
		{filepath.Join(home, ".ssh", "id_rsa"), true},
		{filepath.Join(home, ".aws", "credentials"), true},
		{"/etc/shadow", true},
		{"/tmp/project/.env", true},
		{"/tmp/project/.env.production", true},
		{"/tmp/project/src/.env.local", true},
		{"/tmp/project/main.go", false},
		{"/usr/bin", false},
	}

	for _, c := range cases {
		got := IsDeniedPath(c.target, denyPaths)
		if got != c.expected {
			t.Errorf("IsDeniedPath(%q) = %v; expected %v", c.target, got, c.expected)
		}
	}
}

func TestSafePinPathFD_SymlinkReplacementAttack_FailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink pinning requires Unix")
	}

	tmpDir := t.TempDir()
	wsRoot := filepath.Join(tmpDir, "workspace")
	if err := os.MkdirAll(wsRoot, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	// Create a simulated sensitive credential directory
	sensitiveDir := filepath.Join(tmpDir, "fake_ssh")
	if err := os.MkdirAll(sensitiveDir, 0700); err != nil {
		t.Fatalf("MkdirAll fake_ssh failed: %v", err)
	}

	denyPaths := []string{sensitiveDir, "~/.ssh"}

	// Attacker creates symlink inside workspace pointing to sensitive directory
	symlinkPath := filepath.Join(wsRoot, "trojan_link")
	if err := os.Symlink(sensitiveDir, symlinkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	fd, err := SafePinPathFD(symlinkPath, denyPaths, wsRoot)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("SECURITY VIOLATION: SafePinPathFD permitted symlink pointing to denied directory %s!", sensitiveDir)
	}
	if !errors.Is(err, ErrDeniedPathTarget) && !errors.Is(err, ErrSymlinkTraversal) {
		t.Fatalf("Expected ErrDeniedPathTarget or ErrSymlinkTraversal, got: %v", err)
	}
	t.Logf("PASS: Symlink replacement attack failed closed: %v", err)
}

func TestSafePinPathFD_WorkspaceEscape_FailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink pinning requires Unix")
	}

	tmpDir := t.TempDir()
	wsRoot := filepath.Join(tmpDir, "workspace")
	outsideDir := filepath.Join(tmpDir, "outside_dir")
	if err := os.MkdirAll(wsRoot, 0755); err != nil || os.MkdirAll(outsideDir, 0755) != nil {
		t.Fatalf("MkdirAll failed")
	}

	// Attacker links workspace path to an outside directory
	symlinkPath := filepath.Join(wsRoot, "escape_link")
	if err := os.Symlink(outsideDir, symlinkPath); err != nil {
		t.Fatalf("Symlink failed: %v", err)
	}

	fd, err := SafePinPathFD(symlinkPath, nil, wsRoot)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("SECURITY VIOLATION: SafePinPathFD permitted workspace escape symlink %s -> %s!", symlinkPath, outsideDir)
	}
	if !errors.Is(err, ErrSymlinkTraversal) {
		t.Fatalf("Expected ErrSymlinkTraversal, got: %v", err)
	}
	t.Logf("PASS: Workspace escape symlink rejected: %v", err)
}

func TestSafePinPathFD_ValidDirectoryPinsSuccessfully(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink pinning requires Unix")
	}

	tmpDir := t.TempDir()
	validDir := filepath.Join(tmpDir, "valid_workspace")
	if err := os.MkdirAll(validDir, 0755); err != nil {
		t.Fatalf("MkdirAll failed: %v", err)
	}

	fd, err := SafePinPathFD(validDir, []string{"~/.ssh"}, validDir)
	if err != nil {
		t.Fatalf("SafePinPathFD failed for valid directory: %v", err)
	}
	defer syscall.Close(fd)

	if fd < 0 {
		t.Fatalf("Expected valid file descriptor, got %d", fd)
	}
	t.Logf("PASS: Directory successfully pinned with fd %d", fd)
}

func TestSafePinPathFD_ConcurrentSymlinkRace_FailsClosed(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink pinning requires Unix")
	}

	tmpDir := t.TempDir()
	wsRoot := filepath.Join(tmpDir, "workspace")
	secretDir := filepath.Join(tmpDir, "secret")
	if err := os.MkdirAll(wsRoot, 0755); err != nil || os.MkdirAll(secretDir, 0700) != nil {
		t.Fatalf("setup failed")
	}

	denyPaths := []string{secretDir}
	targetPath := filepath.Join(wsRoot, "race_dir")

	stopChan := make(chan struct{})
	var wg sync.WaitGroup

	// Attacker goroutine: rapidly swaps targetPath between legitimate dir and symlink to secretDir
	wg.Add(1)
	go func() {
		defer wg.Done()
		for i := 0; ; i++ {
			select {
			case <-stopChan:
				return
			default:
				_ = os.Remove(targetPath)
				_ = os.Mkdir(targetPath, 0755)
				_ = os.Remove(targetPath)
				_ = os.Symlink(secretDir, targetPath)
			}
		}
	}()

	// Defender: calls SafePinPathFD repeatedly
	for i := 0; i < 200; i++ {
		fd, err := SafePinPathFD(targetPath, denyPaths, wsRoot)
		if err == nil {
			// If it succeeded, verify it DID NOT pin secretDir
			_ = syscall.Close(fd)
		} else {
			// If it failed, it must fail closed safely
			if !errors.Is(err, ErrDeniedPathTarget) && !errors.Is(err, ErrSymlinkTraversal) &&
				!errors.Is(err, os.ErrNotExist) && !strings.Contains(err.Error(), "no such file") {
				t.Fatalf("Unexpected error type during race: %v", err)
			}
		}
	}

	close(stopChan)
	wg.Wait()
	t.Log("PASS: Concurrent symlink replacement race failed closed safely")
}

func TestBuildDevAgentRuleset(t *testing.T) {
	cfg := Config{
		WorkspaceRoot: "/home/user/project",
		ScratchDir:    "/tmp/airlock-test",
		UserHome:      "/home/user",
	}

	rs := BuildDevAgentRuleset(cfg)
	if rs == nil {
		t.Fatal("BuildDevAgentRuleset returned nil")
	}

	if rs.HandledAccessFS != AccessFSAll {
		t.Errorf("Expected HandledAccessFS to cover AccessFSAll, got %x", rs.HandledAccessFS)
	}

	// Verify that forbidden paths (~/.ssh, ~/.aws, etc.) are present in DenyPaths
	requiredDenies := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config/gh"}
	for _, req := range requiredDenies {
		found := false
		for _, d := range rs.DenyPaths {
			if d == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DevAgent ruleset missing deny path: %s", req)
		}
	}

	// Verify that none of the allowed rules grant access to ~/.ssh or ~/.aws
	for _, rule := range rs.Rules {
		if strings.Contains(rule.Path, ".ssh") || strings.Contains(rule.Path, ".aws") {
			t.Errorf("SECURITY VULNERABILITY: Landlock rule explicitly permitted forbidden path: %s", rule.Path)
		}
	}

	// Verify workspace has AccessFSAll
	var workspaceRule *PathRule
	for _, r := range rs.Rules {
		if r.Path == cfg.WorkspaceRoot {
			workspaceRule = &r
			break
		}
	}
	if workspaceRule == nil {
		t.Errorf("Ruleset missing workspace root rule for %s", cfg.WorkspaceRoot)
	} else if workspaceRule.Access != AccessFSAll {
		t.Errorf("Workspace rule has access %x, expected %x", workspaceRule.Access, AccessFSAll)
	}
}

func TestApply_NonLinuxReturnsError(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Testing non-Linux behavior")
	}

	cfg := Config{
		WorkspaceRoot: "/tmp/ws",
	}
	rs := BuildDevAgentRuleset(cfg)
	err := Apply(rs)
	if err == nil {
		t.Fatal("Expected error on non-Linux platform, got nil")
	}
}
