// Package scratch provides ephemeral workspace allocation with restricted permissions
// and automated orphan scavenging to prevent disk exhaustion.
package scratch

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"
)

// IsPrivatePermissions verifies that directory permissions enforce private access.
// On POSIX systems, this requires strict 0700 permissions. On Windows NTFS (where directory
// POSIX bits are not modeled and os.Stat always reports 0777), any non-error mode is accepted.
func IsPrivatePermissions(mode os.FileMode) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return mode.Perm() == 0700
}

// Manager defines the interface for ephemeral scratch space lifecycle management.
type Manager interface {
	Root() string
	TmpDir() string
	HomeDir() string
	CacheStagingDir() string
	Cleanup() error
}

// DefaultManager manages an ephemeral scratch directory tree.
type DefaultManager struct {
	root            string
	tmpDir          string
	homeDir         string
	cacheStagingDir string
	cleaned         bool
}

// New creates an ephemeral scratch directory under baseDir with 0700 permissions.
func New(baseDir string) (*DefaultManager, error) {
	if baseDir == "" {
		baseDir = os.TempDir()
	}

	// Resolve symlinks (e.g. /tmp -> /private/tmp on macOS)
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err == nil {
		baseDir = resolvedBase
	}

	// Generate 16 cryptographically secure random bytes
	tokenBytes := make([]byte, 16)
	if _, err := rand.Read(tokenBytes); err != nil {
		return nil, fmt.Errorf("scratch: failed to generate random token: %w", err)
	}

	dirName := "boxpkg-" + hex.EncodeToString(tokenBytes)
	rootDir := filepath.Join(baseDir, dirName)

	// Enforce private 0700 permissions: accessible only by current user
	if err := os.Mkdir(rootDir, 0700); err != nil {
		return nil, fmt.Errorf("scratch: failed to create root %s: %w", rootDir, err)
	}

	m := &DefaultManager{
		root:            rootDir,
		tmpDir:          filepath.Join(rootDir, "tmp"),
		homeDir:         filepath.Join(rootDir, "home"),
		cacheStagingDir: filepath.Join(rootDir, "cache-staging"),
	}

	for _, sub := range []string{m.tmpDir, m.homeDir, m.cacheStagingDir} {
		if err := os.Mkdir(sub, 0700); err != nil {
			_ = os.RemoveAll(rootDir)
			return nil, fmt.Errorf("scratch: failed to create subdir %s: %w", sub, err)
		}
	}

	return m, nil
}

// Root returns the root path of the scratch directory.
func (m *DefaultManager) Root() string {
	return m.root
}

// TmpDir returns the scratch temporary directory for compiler objects.
func (m *DefaultManager) TmpDir() string {
	return m.tmpDir
}

// HomeDir returns the virtual HOME directory.
func (m *DefaultManager) HomeDir() string {
	return m.homeDir
}

// CacheStagingDir returns the ephemeral package cache write staging directory.
func (m *DefaultManager) CacheStagingDir() string {
	return m.cacheStagingDir
}

// Cleanup unlinks the scratch directory and all contained files.
func (m *DefaultManager) Cleanup() error {
	if m == nil || m.cleaned || m.root == "" {
		return nil
	}
	m.cleaned = true
	return os.RemoveAll(m.root)
}

// ScavengeOrphans purges abandoned boxpkg-* directories older than maxAge.
// Mitigates disk exhaustion from SIGKILL, OOM killer, or crashes (V-11).
func ScavengeOrphans(baseDir string, maxAge time.Duration) (int, error) {
	if baseDir == "" {
		baseDir = os.TempDir()
	}
	resolvedBase, err := filepath.EvalSymlinks(baseDir)
	if err == nil {
		baseDir = resolvedBase
	}

	entries, err := os.ReadDir(baseDir)
	if err != nil {
		return 0, fmt.Errorf("scratch: failed to read base directory %s: %w", baseDir, err)
	}

	now := time.Now()
	cleaned := 0

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if !strings.HasPrefix(name, "boxpkg-") {
			continue
		}

		fullPath := filepath.Join(baseDir, name)
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if now.Sub(info.ModTime()) > maxAge {
			if err := os.RemoveAll(fullPath); err == nil {
				cleaned++
			}
		}
	}

	return cleaned, nil
}
