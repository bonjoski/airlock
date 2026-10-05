//go:build !windows

package sandbox

import (
	"context"
	"errors"
	"fmt"
)

// WindowsEngine represents the Windows sandbox execution engine stub on non-Windows platforms.
type WindowsEngine struct {
	opts Options
}

// NewWindowsEngine returns an unsupported platform error on non-Windows hosts.
func NewWindowsEngine(opts Options) (*WindowsEngine, error) {
	return nil, fmt.Errorf("sandbox: Windows engine is not supported on %s: %w", "non-windows", errors.ErrUnsupported)
}

// Execute is a stub on non-Windows platforms.
func (w *WindowsEngine) Execute(ctx context.Context, cmdArgs []string) (int, error) {
	return 1, errors.ErrUnsupported
}
