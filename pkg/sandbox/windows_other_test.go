//go:build !windows

package sandbox

import (
	"context"
	"testing"
)

func TestWindowsEngine_NonWindowsUnsupported(t *testing.T) {
	opts := Options{
		WorkspaceRoot: t.TempDir(),
	}

	_, err := NewWindowsEngine(opts)
	if err == nil {
		t.Fatal("Expected NewWindowsEngine to fail on non-Windows host")
	}

	stub := &WindowsEngine{opts: opts}
	_, execErr := stub.Execute(context.Background(), []string{"test"})
	if execErr == nil {
		t.Fatal("Expected Execute to fail on non-Windows host")
	}
}
