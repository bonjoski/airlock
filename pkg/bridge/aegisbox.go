package bridge

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/bonjoski/airlock/pkg/sandbox"
)

// DiscoverAegisbox returns the path to the aegisbox hypervisor binary.
func DiscoverAegisbox() (string, error) {
	if p := os.Getenv("AEGISBOX_PATH"); p != "" {
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			return p, nil
		}
		return "", fmt.Errorf("aegisbox binary specified in AEGISBOX_PATH %q not found or not executable", p)
	}

	if p, err := exec.LookPath("aegisbox"); err == nil {
		return p, nil
	}

	candidates := []string{
		"/usr/local/bin/aegisbox",
		"/opt/homebrew/bin/aegisbox",
		filepath.Join(os.Getenv("HOME"), ".local", "bin", "aegisbox"),
		filepath.Join(os.Getenv("HOME"), "bin", "aegisbox"),
		filepath.Join(os.Getenv("HOME"), "go", "bin", "aegisbox"),
	}

	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() {
			return c, nil
		}
	}

	return "", errors.New("aegisbox binary not found on PATH or standard install locations (set AEGISBOX_PATH to override)")
}

// ExecuteMicroVM bridges execution from Airlock to Aegisbox MicroVM isolation.
func ExecuteMicroVM(ctx context.Context, opts sandbox.Options, cmdArgs []string) (int, error) {
	bin, err := DiscoverAegisbox()
	if err != nil {
		return 1, fmt.Errorf("airlock microvm bridge: %w", err)
	}

	var args []string
	args = append(args, "exec", "-engine", "microvm")

	if opts.Airgap {
		args = append(args, "-airgap")
	}

	if !opts.NonInteractive {
		args = append(args, "-interactive")
	}

	if len(opts.LeasedSecrets) > 0 {
		args = append(args, "-allow-env", strings.Join(opts.LeasedSecrets, ","))
	}

	args = append(args, cmdArgs...)

	cmd := exec.CommandContext(ctx, bin, args...)
	if opts.WorkingDir != "" {
		cmd.Dir = opts.WorkingDir
	} else {
		cmd.Dir = opts.WorkspaceRoot
	}
	cmd.Stdin = opts.Stdin
	cmd.Stdout = opts.Stdout
	cmd.Stderr = opts.Stderr

	if err := cmd.Run(); err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			return exitErr.ExitCode(), nil
		}
		return 1, err
	}

	return 0, nil
}
