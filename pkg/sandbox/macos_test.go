package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestFindWorkspaceRoot(t *testing.T) {
	tempDir := t.TempDir()
	repoRoot := filepath.Join(tempDir, "my-monorepo")
	_ = os.Mkdir(repoRoot, 0755)
	_ = os.WriteFile(filepath.Join(repoRoot, "package.json"), []byte("{}"), 0644)

	deepDir := filepath.Join(repoRoot, "packages", "core", "src")
	_ = os.MkdirAll(deepDir, 0755)

	found := FindWorkspaceRoot(deepDir)
	if found != repoRoot {
		t.Errorf("Expected workspace root %s, got %s", repoRoot, found)
	}
}

func TestMacOSEngine_Execute(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var stdout, stderr bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		Airgap:         true,
		NonInteractive: true,
		Stdout:         &stdout,
		Stderr:         &stderr,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/echo", "airlock_go_engine_test"})
	if err != nil {
		t.Fatalf("Engine.Execute failed: %v (stderr: %s)", err, stderr.String())
	}
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "airlock_go_engine_test") {
		t.Errorf("Expected output not found in stdout: %s", stdout.String())
	}
}

func TestMacOSEngine_ExitCodePropagation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine exit code test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var stdout, stderr bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		Airgap:         true,
		NonInteractive: true,
		Stdout:         &stdout,
		Stderr:         &stderr,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/sh", "-c", "exit 42"})
	if err != nil {
		t.Fatalf("Engine.Execute failed: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("Expected exit code 42, got %d", exitCode)
	}
}

func TestMacOSEngine_NestedBypass(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine nested bypass test on non-darwin platform")
	}

	_ = os.Setenv("__AIRLOCK_ACTIVE", "1")
	defer os.Unsetenv("__AIRLOCK_ACTIVE")

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var stdout bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		NonInteractive: true,
		Stdout:         &stdout,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/echo", "nested_bypass_ok"})
	if err != nil {
		t.Fatalf("Nested execution failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "nested_bypass_ok") {
		t.Errorf("Expected output not found: %s", stdout.String())
	}
}
