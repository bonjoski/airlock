//go:build windows

package sandbox

import (
	"context"
	"os"
	"testing"
)

func TestWindowsEngine_NestedBypass(t *testing.T) {
	origVal := os.Getenv("__AIRLOCK_ACTIVE")
	_ = os.Setenv("__AIRLOCK_ACTIVE", "1")
	defer func() {
		_ = os.Setenv("__AIRLOCK_ACTIVE", origVal)
	}()

	tempDir := t.TempDir()
	opts := Options{
		WorkspaceRoot: tempDir,
	}

	eng, err := NewWindowsEngine(opts)
	if err != nil {
		t.Fatalf("NewWindowsEngine failed: %v", err)
	}

	code, err := eng.Execute(context.Background(), []string{"cmd.exe", "/c", "exit 0"})
	if err != nil {
		t.Fatalf("Nested execution failed: %v", err)
	}
	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}
}

func TestWindowsEngine_BasicExecution(t *testing.T) {
	tempDir := t.TempDir()
	opts := Options{
		WorkspaceRoot:  tempDir,
		Airgap:         true,
		NonInteractive: true,
	}

	eng, err := NewWindowsEngine(opts)
	if err != nil {
		t.Fatalf("NewWindowsEngine failed: %v", err)
	}

	code, err := eng.Execute(context.Background(), []string{"cmd.exe", "/c", "exit 0"})
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}
	if code != 0 {
		t.Errorf("Expected exit code 0, got %d", code)
	}
}
