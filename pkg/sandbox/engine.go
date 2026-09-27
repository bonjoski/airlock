// Package sandbox defines the core confinement engine interface and platform implementations.
package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/vet"
)

// Options holds runtime parameters for sandboxed execution.
type Options struct {
	WorkspaceRoot  string
	Airgap         bool
	AllowDirectNet bool
	AllowedDomains []string
	KeepEnv        []string
	NonInteractive bool
	ScratchBase    string
	AuditLogger    audit.Logger // Optional structured telemetry logger
	VetEnabled     bool         // Enable Argus static analysis inspection
	VetStrict      bool         // Fail closed on high/critical security findings
	VetTool        string       // Path to external vetpkg/argus tool
	Inspector      vet.Inspector // Injected inspector interface
	Stdout         io.Writer
	Stderr         io.Writer
	Stdin          io.Reader
}

// Engine defines the common execution interface for process confinement backends (OCP/LSP).
type Engine interface {
	Execute(ctx context.Context, cmdArgs []string) (int, error)
}

// NewEngine creates the appropriate sandboxing engine for the host platform.
func NewEngine(opts Options) (Engine, error) {
	if opts.WorkspaceRoot == "" {
		cwd, err := os.Getwd()
		if err != nil {
			return nil, fmt.Errorf("sandbox: failed to determine working directory: %w", err)
		}
		opts.WorkspaceRoot = FindWorkspaceRoot(cwd)
	}

	// Canonicalize workspace path to resolve symlinks
	if resolved, err := filepath.EvalSymlinks(opts.WorkspaceRoot); err == nil {
		opts.WorkspaceRoot = resolved
	}

	switch runtime.GOOS {
	case "darwin":
		return NewMacOSEngine(opts)
	case "linux":
		return NewLinuxEngine(opts)
	default:
		return nil, fmt.Errorf("sandbox: operating system %s is not supported: %w", runtime.GOOS, errors.ErrUnsupported)
	}
}

// FindWorkspaceRoot ascends the directory hierarchy to identify the true repository or workspace root.
// It checks for monorepo and VCS anchors (.git, pnpm-workspace.yaml, Cargo.lock, package.json).
func FindWorkspaceRoot(startDir string) string {
	curr := filepath.Clean(startDir)

	for {
		markers := []string{
			".git",
			"pnpm-workspace.yaml",
			"lerna.json",
			"Cargo.lock",
			"package.json",
			"pyproject.toml",
			"go.mod",
		}

		for _, marker := range markers {
			target := filepath.Join(curr, marker)
			if _, err := os.Stat(target); err == nil {
				return curr
			}
		}

		parent := filepath.Dir(curr)
		if parent == curr || parent == "." || parent == "/" {
			break
		}
		curr = parent
	}

	return startDir
}
