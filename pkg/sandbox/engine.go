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
	"strings"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/vet"
)

// SandboxOpts holds runtime parameters and policies for sandboxed execution.
type SandboxOpts struct {
	WorkspaceRoot   string
	WorkingDir      string // Preserved working directory for executed commands
	Profile         string // Execution profile ("standard", "agent", "strict", "airgap", "default")
	ConfigPath      string
	Airgap          bool
	AllowDirectNet  bool
	AllowedDomains  []string
	KeepEnv         []string
	DenyEnv         []string
	ExtraAllowRead  []string
	ExtraAllowWrite []string
	ExtraDenyRead   []string
	ExtraDenyWrite  []string
	NonInteractive  bool
	ScratchBase     string
	AuditLogger     audit.Logger        // Optional structured telemetry logger
	VetEnabled      bool                // Enable Argus static analysis inspection
	VetStrict       bool                // Fail closed on high/critical security findings
	VetTool         string              // Path to external vetpkg/argus tool
	IgnoredVetRules []string            // Argus rule IDs to ignore
	Inspector       vet.Inspector       // Injected inspector interface
	PromptHandler   proxy.PromptHandler // Dynamic capability prompter
	LeasedSecrets   []string            // Secret keys to dynamically lease via Locksmith ETX
	LocksmithSocket string              // Explicit Locksmith socket path (optional)
	SessionTicket   string              // Optional session ticket for batch execution
	Stdout          io.Writer
	Stderr          io.Writer
	Stdin           io.Reader
}

// Options is an alias for SandboxOpts to maintain backwards compatibility.
type Options = SandboxOpts

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

	if opts.WorkingDir != "" {
		if resolved, err := filepath.EvalSymlinks(opts.WorkingDir); err == nil {
			opts.WorkingDir = resolved
		}
	}

	if opts.WorkingDir == "" {
		if cwd, err := os.Getwd(); err == nil {
			if resolved, err := filepath.EvalSymlinks(cwd); err == nil {
				cwd = resolved
			}
			rel, relErr := filepath.Rel(opts.WorkspaceRoot, cwd)
			if relErr == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
				opts.WorkingDir = cwd
			} else {
				opts.WorkingDir = opts.WorkspaceRoot
			}
		} else {
			opts.WorkingDir = opts.WorkspaceRoot
		}
	} else {
		rel, relErr := filepath.Rel(opts.WorkspaceRoot, opts.WorkingDir)
		if relErr != nil || strings.HasPrefix(rel, "..") || rel == ".." {
			opts.WorkingDir = opts.WorkspaceRoot
		}
	}

	switch runtime.GOOS {
	case "darwin":
		return NewMacOSEngine(opts)
	case "linux":
		return NewLinuxEngine(opts)
	case "windows":
		return NewWindowsEngine(opts)
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
			"pom.xml",
			"build.gradle",
			"build.gradle.kts",
			"settings.gradle",
			"settings.gradle.kts",
			"Gemfile",
			"Gemfile.lock",
			"Package.swift",
			"Package.resolved",
			"Podfile",
			"Podfile.lock",
			"global.json",
			"nuget.config",
			"Dockerfile",
			"docker-compose.yaml",
			"docker-compose.yml",
			"compose.yaml",
			"compose.yml",
			"Chart.yaml",
			"kustomization.yaml",
		}

		for _, marker := range markers {
			target := filepath.Join(curr, marker)
			if _, err := os.Stat(target); err == nil {
				return curr
			}
		}

		// Check for .NET solution or project files, and Apple Xcode workspaces
		if matches, _ := filepath.Glob(filepath.Join(curr, "*.sln")); len(matches) > 0 {
			return curr
		}
		if matches, _ := filepath.Glob(filepath.Join(curr, "*.csproj")); len(matches) > 0 {
			return curr
		}
		if matches, _ := filepath.Glob(filepath.Join(curr, "*.xcworkspace")); len(matches) > 0 {
			return curr
		}
		if matches, _ := filepath.Glob(filepath.Join(curr, "*.xcodeproj")); len(matches) > 0 {
			return curr
		}

		parent := filepath.Dir(curr)
		if parent == curr || parent == "." || parent == "/" || parent == "\\" || parent == filepath.VolumeName(parent)+"\\" || parent == filepath.VolumeName(parent) {
			break
		}
		curr = parent
	}

	return startDir
}
