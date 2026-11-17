// Package mcp provides the Airlock + Bomhound Hermetic MCP Execution Wrapper
// and MCP protocol server/tool implementations.
package mcp

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/sandbox"
)

var (
	// ErrLockfileNotFound is returned when the specified lockfile path does not exist.
	ErrLockfileNotFound = errors.New("lockfile not found")
	// ErrLockfileIntegrityFailed is returned when the bundle hash does not match lockfile contents.
	ErrLockfileIntegrityFailed = errors.New("lockfile integrity check failed: digest mismatch")
	// ErrEmptyCommand is returned when no command is provided for execution.
	ErrEmptyCommand = errors.New("no command specified for MCP server execution")
	// ErrInvalidLockfile is returned when lockfile format is corrupted or unparseable.
	ErrInvalidLockfile = errors.New("invalid lockfile format")
)

// CommandType categorizes the detected MCP execution runtime.
type CommandType string

const (
	CommandTypeNPX     CommandType = "npx"
	CommandTypeUVX     CommandType = "uvx"
	CommandTypeGeneric CommandType = "generic"
)

// Lockfile represents an immutable sealed specification of the MCP execution bundle.
type Lockfile struct {
	Version    int               `json:"version"`
	BundleHash string            `json:"bundle_hash"`
	Command    []string          `json:"command"`
	Packages   map[string]string `json:"packages,omitempty"`
	CreatedAt  string            `json:"created_at,omitempty"`
}

// LauncherConfig contains parameters for hermetic MCP server execution.
type LauncherConfig struct {
	Lockfile     string    // Optional path to verified lockfile
	CacheDir     string    // Path to immutable offline wheelhouse / package cache (default: ~/.airlock/mcp-cache)
	AllowNetwork string    // Optional allowlisted host:port (default: zero WAN egress)
	Workspace    string    // Designated project root (default: current working directory or detected root)
	Stdin        io.Reader // Standard input stream
	Stdout       io.Writer // Standard output stream
	Stderr       io.Writer // Standard error stream
}

// EngineLoader is a factory function for instantiating the sandbox engine (allows test mock injection).
type EngineLoader func(opts sandbox.SandboxOpts) (sandbox.Engine, error)

// Launcher coordinates verification, offline caching, and sandboxed execution of MCP servers.
type Launcher struct {
	cfg          LauncherConfig
	engineLoader EngineLoader
}

// LauncherOption configures a Launcher.
type LauncherOption func(*Launcher)

// WithEngineLoader sets a custom engine loader (useful for testing).
func WithEngineLoader(loader EngineLoader) LauncherOption {
	return func(l *Launcher) {
		l.engineLoader = loader
	}
}

// NewLauncher creates a new Launcher with the provided configuration.
func NewLauncher(cfg LauncherConfig, opts ...LauncherOption) *Launcher {
	if cfg.CacheDir == "" {
		home, err := os.UserHomeDir()
		if err == nil {
			cfg.CacheDir = filepath.Join(home, ".airlock", "mcp-cache")
		} else {
			cfg.CacheDir = filepath.Join(os.TempDir(), "airlock-mcp-cache")
		}
	}
	if cfg.Stdin == nil {
		cfg.Stdin = os.Stdin
	}
	if cfg.Stdout == nil {
		cfg.Stdout = os.Stdout
	}
	if cfg.Stderr == nil {
		cfg.Stderr = os.Stderr
	}

	l := &Launcher{
		cfg:          cfg,
		engineLoader: sandbox.NewEngine,
	}

	for _, opt := range opts {
		opt(l)
	}

	return l
}

// DetectCommandType inspects command arguments and identifies if it is npx, uvx, or generic.
func DetectCommandType(cmd []string) CommandType {
	if len(cmd) == 0 {
		return CommandTypeGeneric
	}

	target := cmd[0]
	// Handle /usr/bin/env <cmd>
	if filepath.Base(target) == "env" && len(cmd) > 1 {
		for i := 1; i < len(cmd); i++ {
			if !strings.HasPrefix(cmd[i], "-") {
				target = cmd[i]
				break
			}
		}
	}

	bin := strings.ToLower(filepath.Base(target))
	switch {
	case bin == "npx" || bin == "npm" || strings.HasPrefix(bin, "npx") || strings.HasPrefix(bin, "npm"):
		return CommandTypeNPX
	case bin == "uvx" || bin == "uv" || bin == "pip" || bin == "pip3" || strings.HasPrefix(bin, "uvx") || strings.HasPrefix(bin, "uv"):
		return CommandTypeUVX
	default:
		// Check full command args for embedded npx/uvx invocations
		for _, arg := range cmd {
			argLower := strings.ToLower(filepath.Base(arg))
			if argLower == "npx" || argLower == "npm" {
				return CommandTypeNPX
			}
			if argLower == "uvx" || argLower == "uv" || argLower == "pip" || argLower == "pip3" {
				return CommandTypeUVX
			}
		}
		return CommandTypeGeneric
	}
}

// ComputeBundleFingerprint computes a SHA-256 digest representing the execution bundle and command.
func ComputeBundleFingerprint(cmd []string) string {
	h := sha256.New()
	for _, arg := range cmd {
		h.Write([]byte(arg))
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil))
}

// GetOfflineEnv returns environment variables for forcing offline execution without network resolution drift.
func GetOfflineEnv(cmdType CommandType, cacheDir string) []string {
	npmCache := filepath.Join(cacheDir, "npm")
	wheelsDir := filepath.Join(cacheDir, "wheels")
	uvCache := filepath.Join(cacheDir, "uv")

	switch cmdType {
	case CommandTypeNPX:
		return []string{
			"npm_config_offline=true",
			fmt.Sprintf("npm_config_cache=%s", npmCache),
		}
	case CommandTypeUVX:
		return []string{
			"PIP_NO_INDEX=true",
			"UV_NO_SYNC=1",
			fmt.Sprintf("PIP_FIND_LINKS=%s", wheelsDir),
			fmt.Sprintf("UV_CACHE_DIR=%s", uvCache),
		}
	default:
		return []string{
			"npm_config_offline=true",
			fmt.Sprintf("npm_config_cache=%s", npmCache),
			"PIP_NO_INDEX=true",
			"UV_NO_SYNC=1",
			fmt.Sprintf("PIP_FIND_LINKS=%s", wheelsDir),
			fmt.Sprintf("UV_CACHE_DIR=%s", uvCache),
		}
	}
}

// VerifyLockfile inspects the lockfile at the given path and asserts its bundle hash matches the command.
func VerifyLockfile(lockfilePath string, cmd []string) (*Lockfile, error) {
	data, err := os.ReadFile(lockfilePath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, fmt.Errorf("%w: %s", ErrLockfileNotFound, lockfilePath)
		}
		return nil, fmt.Errorf("failed to read lockfile: %w", err)
	}

	var lf Lockfile
	if err := json.Unmarshal(data, &lf); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrInvalidLockfile, err)
	}

	expectedHash := ComputeBundleFingerprint(cmd)
	if lf.BundleHash != expectedHash {
		return nil, fmt.Errorf("%w: expected %s, got %s", ErrLockfileIntegrityFailed, expectedHash, lf.BundleHash)
	}

	return &lf, nil
}

// CreateLockfile writes a sealed, verified lockfile for the given command to the designated path.
func CreateLockfile(lockfilePath string, cmd []string) (*Lockfile, error) {
	lf := &Lockfile{
		Version:    1,
		BundleHash: ComputeBundleFingerprint(cmd),
		Command:    cmd,
		CreatedAt:  time.Now().UTC().Format(time.RFC3339),
	}

	data, err := json.MarshalIndent(lf, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to marshal lockfile: %w", err)
	}

	if err := os.MkdirAll(filepath.Dir(lockfilePath), 0755); err != nil {
		return nil, fmt.Errorf("failed to create lockfile directory: %w", err)
	}

	if err := os.WriteFile(lockfilePath, data, 0644); err != nil {
		return nil, fmt.Errorf("failed to write lockfile: %w", err)
	}

	return lf, nil
}

// Launch prepares hermetic caching, verifies lockfile integrity, injects offline environment variables,
// and spawns the MCP server within Airlock's Tier 1 kernel sandbox runner.
func (l *Launcher) Launch(ctx context.Context, cmd []string) (int, error) {
	if len(cmd) == 0 {
		return 1, ErrEmptyCommand
	}

	// 1. Intercept command and determine runtime type
	cmdType := DetectCommandType(cmd)

	// 2. Lockfile integrity check or auto-freeze
	bundleHash := ComputeBundleFingerprint(cmd)
	serverCacheDir := filepath.Join(l.cfg.CacheDir, bundleHash)

	if l.cfg.Lockfile != "" {
		if _, err := VerifyLockfile(l.cfg.Lockfile, cmd); err != nil {
			return 1, fmt.Errorf("airlock mcp: %w", err)
		}
	} else {
		// Auto-freeze lockfile in cache dir if --lockfile is omitted
		cacheLockfile := filepath.Join(serverCacheDir, "lock.json")
		if _, err := os.Stat(cacheLockfile); err == nil {
			if _, err := VerifyLockfile(cacheLockfile, cmd); err != nil {
				return 1, fmt.Errorf("airlock mcp: cached %w", err)
			}
		} else {
			if _, err := CreateLockfile(cacheLockfile, cmd); err != nil {
				return 1, fmt.Errorf("airlock mcp: failed to freeze lockfile: %w", err)
			}
		}
	}

	// 3. Inject offline execution environment variables to prevent runtime transitive resolution drift
	offlineEnv := GetOfflineEnv(cmdType, l.cfg.CacheDir)

	// Ensure cache subdirectories exist
	_ = os.MkdirAll(filepath.Join(l.cfg.CacheDir, "npm"), 0755)
	_ = os.MkdirAll(filepath.Join(l.cfg.CacheDir, "wheels"), 0755)
	_ = os.MkdirAll(filepath.Join(l.cfg.CacheDir, "uv"), 0755)
	_ = os.MkdirAll(serverCacheDir, 0755)

	// 4. Configure Tier 1 Sandbox Runner Options
	workspaceRoot := l.cfg.Workspace
	if workspaceRoot == "" {
		if cwd, err := os.Getwd(); err == nil {
			workspaceRoot = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	keepEnv := []string{
		"npm_config_offline",
		"npm_config_cache",
		"PIP_NO_INDEX",
		"UV_NO_SYNC",
		"PIP_FIND_LINKS",
		"UV_CACHE_DIR",
	}

	opts := sandbox.SandboxOpts{
		Profile:        "mcp",
		WorkspaceRoot:  workspaceRoot,
		CacheDir:       l.cfg.CacheDir,
		AllowNetwork:   l.cfg.AllowNetwork,
		ExtraEnv:       offlineEnv,
		KeepEnv:        keepEnv,
		ExtraAllowRead: []string{l.cfg.CacheDir, serverCacheDir},
		Stdin:          l.cfg.Stdin,
		Stdout:         l.cfg.Stdout,
		Stderr:         l.cfg.Stderr,
	}

	// 5. Execute within Tier 1 Sandbox Engine
	engine, err := l.engineLoader(opts)
	if err != nil {
		return 1, fmt.Errorf("airlock mcp: failed to initialize sandbox engine: %w", err)
	}

	return engine.Execute(ctx, cmd)
}
