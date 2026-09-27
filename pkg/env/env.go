// Package env provides zero-trust environment variable sanitization
// for sandboxed process execution.
package env

import (
	"os"
	"path/filepath"
	"strings"
)

// SafeEnvAllowlist defines standard POSIX environment variables safe to inherit.
// Any environment variable not in this list or explicitly preserved via KeepEnv is dropped.
var SafeEnvAllowlist = map[string]bool{
	"PATH":            true,
	"TERM":            true,
	"TERMINFO":        true,
	"LANG":            true,
	"LC_ALL":          true,
	"LC_CTYPE":        true,
	"LC_MESSAGES":     true,
	"TZ":              true,
	"USER":            true,
	"LOGNAME":         true,
	"SHELL":           true,
	"CI":              true,
	"DEBIAN_FRONTEND": true,
}

// Config specifies options for environment sanitization.
type Config struct {
	VirtualHome  string   // Path to ephemeral virtual $HOME directory
	ScratchDir   string   // Path to ephemeral scratch space ($TMPDIR)
	StagingCache string   // Path to isolated cache staging directory
	ProxyURL     string   // Optional proxy URL, e.g. "http://127.0.0.1:18443"
	KeepEnv      []string // Additional variables explicitly allowed by user
}

// Sanitizer provides an interface for environment transformation.
type Sanitizer interface {
	Sanitize(hostEnv []string) []string
}

// DefaultSanitizer implements standard POSIX allowlist sanitization.
type DefaultSanitizer struct {
	config Config
}

// NewSanitizer creates a new environment sanitizer with the given configuration.
func NewSanitizer(cfg Config) *DefaultSanitizer {
	return &DefaultSanitizer{config: cfg}
}

// Sanitize filters host environment variables, purges unsafe relative entries from PATH,
// injects virtual paths, and exports the nesting sentinel __AIRLOCK_ACTIVE=1.
func (s *DefaultSanitizer) Sanitize(hostEnv []string) []string {
	keepSet := make(map[string]bool, len(s.config.KeepEnv))
	for _, k := range s.config.KeepEnv {
		keepSet[strings.TrimSpace(k)] = true
	}

	result := make([]string, 0, len(hostEnv)+8)

	for _, entry := range hostEnv {
		idx := strings.Index(entry, "=")
		if idx == -1 {
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]

		// Explicit keep-env overrides take precedence
		if keepSet[key] {
			result = append(result, entry)
			continue
		}

		// Drop variables not on the allowlist (e.g. AWS_*, DATABASE_URL, GITHUB_TOKEN)
		if !SafeEnvAllowlist[key] {
			continue
		}

		// Sanitize PATH to eliminate relative trojan binaries
		if key == "PATH" {
			val = SanitizePath(val)
		}

		// HOME and TMPDIR are overridden with virtual paths below
		if key == "HOME" || key == "TMPDIR" {
			continue
		}

		result = append(result, key+"="+val)
	}

	// Inject virtual paths
	if s.config.VirtualHome != "" {
		result = append(result, "HOME="+s.config.VirtualHome)
	}
	if s.config.ScratchDir != "" {
		result = append(result, "TMPDIR="+s.config.ScratchDir)
	}

	// Inject cache redirects to ephemeral staging layer (V-12)
	if s.config.StagingCache != "" {
		result = append(result,
			"npm_config_cache="+filepath.Join(s.config.StagingCache, "npm"),
			"YARN_CACHE_FOLDER="+filepath.Join(s.config.StagingCache, "yarn"),
			"PIP_CACHE_DIR="+filepath.Join(s.config.StagingCache, "pip"),
			"UV_CACHE_DIR="+filepath.Join(s.config.StagingCache, "uv"),
			"CARGO_TARGET_DIR="+filepath.Join(s.config.StagingCache, "cargo-target"),
		)
	}

	// Inject proxy configuration if active
	if s.config.ProxyURL != "" {
		result = append(result,
			"HTTP_PROXY="+s.config.ProxyURL,
			"HTTPS_PROXY="+s.config.ProxyURL,
			"http_proxy="+s.config.ProxyURL,
			"https_proxy="+s.config.ProxyURL,
			"npm_config_proxy="+s.config.ProxyURL,
			"PIP_PROXY="+s.config.ProxyURL,
		)
	}

	// Export nesting sentinel to prevent recursive sandboxing crashes in agent loops
	result = append(result, "__AIRLOCK_ACTIVE=1")

	return result
}

// SanitizePath strips relative directories (e.g. ".", "./bin", "node_modules/.bin")
// from the PATH variable to prevent trojan binary execution.
func SanitizePath(pathVar string) string {
	entries := filepath.SplitList(pathVar)
	cleanEntries := make([]string, 0, len(entries))

	for _, entry := range entries {
		entry = strings.TrimSpace(entry)
		if entry == "" {
			continue
		}

		// Must be absolute path
		if !filepath.IsAbs(entry) {
			continue
		}

		clean := filepath.Clean(entry)
		if clean == "/" {
			continue
		}

		cleanEntries = append(cleanEntries, clean)
	}

	return strings.Join(cleanEntries, string(os.PathListSeparator))
}
