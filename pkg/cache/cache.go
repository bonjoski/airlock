// Package cache manages read-only host package cache mounts and
// post-execution atomic synchronization from ephemeral staging directories.
package cache

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

var (
	// ErrSymlinkRejected is returned when an untrusted symlink is detected in staging cache.
	ErrSymlinkRejected = errors.New("cache: untrusted symlink detected in cache staging layer")
	// ErrPathTraversal is returned when an invalid path traversal attempt is detected.
	ErrPathTraversal = errors.New("cache: illegal path traversal attempt in staging file")
)

// Mount describes a host directory to bind into the sandbox.
type Mount struct {
	HostPath string
	ReadOnly bool
}

// ToolCacheMapping links a package manager cache name to its default host path and staging subdir.
type ToolCacheMapping struct {
	Name        string
	Subdir      string
	HostRelPath string // Relative to userHome
	EnvVar      string
}

// DefaultToolMappings returns standard package manager cache definitions.
func DefaultToolMappings() []ToolCacheMapping {
	return []ToolCacheMapping{
		{
			Name:        "npm",
			Subdir:      "npm",
			HostRelPath: ".npm",
			EnvVar:      "npm_config_cache",
		},
		{
			Name:        "yarn",
			Subdir:      "yarn",
			HostRelPath: filepath.Join(".cache", "yarn"),
			EnvVar:      "YARN_CACHE_FOLDER",
		},
		{
			Name:        "pnpm",
			Subdir:      "pnpm",
			HostRelPath: filepath.Join(".local", "share", "pnpm", "store"),
			EnvVar:      "",
		},
		{
			Name:        "pip",
			Subdir:      "pip",
			HostRelPath: filepath.Join(".cache", "pip"),
			EnvVar:      "PIP_CACHE_DIR",
		},
		{
			Name:        "uv",
			Subdir:      "uv",
			HostRelPath: filepath.Join(".cache", "uv"),
			EnvVar:      "UV_CACHE_DIR",
		},
		{
			Name:        "cargo-registry",
			Subdir:      "cargo-registry",
			HostRelPath: filepath.Join(".cargo", "registry"),
			EnvVar:      "",
		},
		{
			Name:        "cargo-git",
			Subdir:      "cargo-git",
			HostRelPath: filepath.Join(".cargo", "git"),
			EnvVar:      "",
		},
		{
			Name:        "go-mod",
			Subdir:      "go-mod",
			HostRelPath: filepath.Join("go", "pkg", "mod"),
			EnvVar:      "GOMODCACHE",
		},
		{
			Name:        "go-build",
			Subdir:      "go-build",
			HostRelPath: filepath.Join(".cache", "go-build"),
			EnvVar:      "GOCACHE",
		},
	}
}

// StagingConfig contains provisioned paths and environment variables for sandboxed processes.
type StagingConfig struct {
	BaseDir string
	EnvVars map[string]string
}

// Manager defines the interface for host cache mounting and safe staging sync.
type Manager interface {
	GetHostCacheMounts(userHome string) []Mount
	ProvisionStaging(stagingBase string) (*StagingConfig, error)
	SyncBack(stagingBase string, userHome string) error
}

// DefaultManager implements standard read-only host caching and validated post-exec sync.
type DefaultManager struct {
	mappings []ToolCacheMapping
}

// NewManager creates a new cache manager with default tool mappings.
func NewManager() *DefaultManager {
	return &DefaultManager{
		mappings: DefaultToolMappings(),
	}
}

// GetHostCacheMounts returns the host paths that should be mounted read-only into the sandbox.
func (m *DefaultManager) GetHostCacheMounts(userHome string) []Mount {
	if userHome == "" {
		return nil
	}

	mounts := make([]Mount, 0, len(m.mappings))
	seen := make(map[string]bool)

	for _, mapping := range m.mappings {
		hostPath := filepath.Join(userHome, mapping.HostRelPath)
		if !seen[hostPath] {
			seen[hostPath] = true
			mounts = append(mounts, Mount{
				HostPath: hostPath,
				ReadOnly: true,
			})
		}
	}

	return mounts
}

// ProvisionStaging creates isolated staging subdirectories under stagingBase and returns environment variables.
func (m *DefaultManager) ProvisionStaging(stagingBase string) (*StagingConfig, error) {
	if stagingBase == "" {
		return nil, errors.New("cache: staging base path cannot be empty")
	}

	envVars := make(map[string]string)

	for _, mapping := range m.mappings {
		targetDir := filepath.Join(stagingBase, mapping.Subdir)
		if err := os.MkdirAll(targetDir, 0700); err != nil {
			return nil, fmt.Errorf("cache: failed to provision staging directory for %s: %w", mapping.Name, err)
		}
		if mapping.EnvVar != "" {
			envVars[mapping.EnvVar] = targetDir
		}
	}

	return &StagingConfig{
		BaseDir: stagingBase,
		EnvVars: envVars,
	}, nil
}

// SyncBack atomically and safely synchronizes newly downloaded cache entries from
// the ephemeral staging directory back to the host cache directory on successful execution.
// It verifies against directory traversal, rejects symlinks, and performs atomic rename operations.
func (m *DefaultManager) SyncBack(stagingBase string, userHome string) error {
	if stagingBase == "" || userHome == "" {
		return nil
	}

	// Verify stagingBase exists
	if _, err := os.Stat(stagingBase); os.IsNotExist(err) {
		return nil
	}

	for _, mapping := range m.mappings {
		stagingSubdir := filepath.Join(stagingBase, mapping.Subdir)
		hostTargetDir := filepath.Join(userHome, mapping.HostRelPath)

		if err := m.syncDirectory(stagingSubdir, hostTargetDir); err != nil {
			return fmt.Errorf("cache: failed to sync %s cache: %w", mapping.Name, err)
		}
	}

	return nil
}

func (m *DefaultManager) syncDirectory(stagingDir string, hostDir string) error {
	info, err := os.Stat(stagingDir)
	if os.IsNotExist(err) || !info.IsDir() {
		return nil
	}

	entries, err := os.ReadDir(stagingDir)
	if err != nil {
		return fmt.Errorf("cache: failed to inspect staging dir %s: %w", stagingDir, err)
	}
	if len(entries) == 0 {
		return nil // Nothing staged
	}

	return filepath.Walk(stagingDir, func(currentPath string, currentInfo os.FileInfo, walkErr error) error {
		if walkErr != nil {
			return fmt.Errorf("cache: walk error on %s: %w", currentPath, walkErr)
		}

		if currentPath == stagingDir {
			return nil
		}

		relPath, err := filepath.Rel(stagingDir, currentPath)
		if err != nil {
			return fmt.Errorf("cache: failed to compute relative path: %w", err)
		}

		// Security Check 1: Reject path traversal
		if strings.Contains(relPath, "..") || filepath.IsAbs(relPath) {
			return fmt.Errorf("%w: %s", ErrPathTraversal, relPath)
		}

		// Security Check 2: Reject symlinks to prevent host file overwrite or redirection
		if currentInfo.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %s", ErrSymlinkRejected, relPath)
		}

		targetHostPath := filepath.Join(hostDir, relPath)

		// If directory, ensure host directory exists with 0755
		if currentInfo.IsDir() {
			if mkErr := os.MkdirAll(targetHostPath, 0755); mkErr != nil {
				return fmt.Errorf("cache: failed to create host cache dir %s: %w", targetHostPath, mkErr)
			}
			return nil
		}

		// If regular file, atomically copy
		if currentInfo.Mode().IsRegular() {
			if copyErr := copyFileAtomic(currentPath, targetHostPath, currentInfo.Mode().Perm()); copyErr != nil {
				return fmt.Errorf("cache: failed to atomically copy %s to host: %w", relPath, copyErr)
			}
		}

		return nil
	})
}

// copyFileAtomic safely copies src to dst using an ephemeral temp file in dst's directory,
// followed by an atomic rename.
func copyFileAtomic(src, dst string, perm os.FileMode) error {
	parentDir := filepath.Dir(dst)
	if err := os.MkdirAll(parentDir, 0755); err != nil {
		return fmt.Errorf("cache: failed to ensure parent directory for %s: %w", dst, err)
	}

	// Generate random suffix for temp file
	randBytes := make([]byte, 8)
	if _, err := rand.Read(randBytes); err != nil {
		return fmt.Errorf("cache: failed to generate random token: %w", err)
	}
	tmpDst := dst + ".tmp." + hex.EncodeToString(randBytes)

	srcFile, err := os.Open(src)
	if err != nil {
		return fmt.Errorf("cache: failed to open source %s: %w", src, err)
	}
	defer srcFile.Close()

	dstFile, err := os.OpenFile(tmpDst, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, perm)
	if err != nil {
		return fmt.Errorf("cache: failed to open temp destination %s: %w", tmpDst, err)
	}

	if _, err := io.Copy(dstFile, srcFile); err != nil {
		_ = dstFile.Close()
		if rmErr := os.Remove(tmpDst); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("cache: copy failed (%w) and cleanup error: %v", err, rmErr)
		}
		return fmt.Errorf("cache: failed to copy contents: %w", err)
	}

	if err := dstFile.Sync(); err != nil {
		_ = dstFile.Close()
		if rmErr := os.Remove(tmpDst); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("cache: sync failed (%w) and cleanup error: %v", err, rmErr)
		}
		return fmt.Errorf("cache: failed to sync temp file: %w", err)
	}

	if err := dstFile.Close(); err != nil {
		if rmErr := os.Remove(tmpDst); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("cache: close failed (%w) and cleanup error: %v", err, rmErr)
		}
		return fmt.Errorf("cache: failed to close temp destination: %w", err)
	}

	if err := os.Rename(tmpDst, dst); err != nil {
		if rmErr := os.Remove(tmpDst); rmErr != nil && !os.IsNotExist(rmErr) {
			return fmt.Errorf("cache: rename failed (%w) and cleanup error: %v", err, rmErr)
		}
		return fmt.Errorf("cache: failed to atomically replace destination %s: %w", dst, err)
	}

	return nil
}
