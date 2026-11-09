// Package env provides zero-trust environment variable sanitization
// for sandboxed process execution.
package env

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
)

// SafeEnvAllowlist defines standard POSIX and Windows environment variables safe to inherit.
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
	// Modern Language Runtimes: Go (AIR-08: GOFLAGS, GOPROXY excluded to prevent build/proxy hijacking)
	"GODEBUG":     true,
	"GOROOT":      true,
	"GOPATH":      true,
	"GOCACHE":     true,
	"GOMODCACHE":  true,
	"GONOSUMDB":   true,
	"GOPRIVATE":   true,
	"CGO_ENABLED": true,
	"GOOS":        true,
	"GOARCH":      true,

	// Modern Language Runtimes: Rust
	"CARGO_HOME":       true,
	"RUSTUP_HOME":      true,
	"RUST_LOG":         true,
	"RUST_BACKTRACE":   true,
	"CARGO_TARGET_DIR": true,

	// Modern Language Runtimes: Node / JavaScript (AIR-08: NODE_PATH, NPM_CONFIG_REGISTRY excluded)
	"NODE_ENV": true,

	// Modern Language Runtimes: Python (AIR-08: PYTHONPATH, PIP_INDEX_URL excluded)
	"PYTHONUNBUFFERED":        true,
	"PYTHONDONTWRITEBYTECODE": true,
	"UV_CACHE_DIR":            true,

	// Windows NT System Environment Variables
	"SYSTEMROOT":              true,
	"SYSTEMDRIVE":             true,
	"WINDIR":                  true,
	"PATHEXT":                 true,
	"COMSPEC":                 true,
	"TEMP":                    true,
	"TMP":                     true,
	"USERPROFILE":             true,
	"LOCALAPPDATA":            true,
	"APPDATA":                 true,
	"ALLUSERSPROFILE":         true,
	"PROGRAMDATA":             true,
	"PROGRAMFILES":            true,
	"PROGRAMFILES(X86)":       true,
	"COMMONPROGRAMFILES":      true,
	"COMMONPROGRAMFILES(X86)": true,
	"NUMBER_OF_PROCESSORS":    true,
	"PROCESSOR_ARCHITECTURE":  true,
	"PROCESSOR_IDENTIFIER":    true,
	"PROCESSOR_LEVEL":         true,
	"PROCESSOR_REVISION":      true,
	"OS":                      true,
	"HOMEDRIVE":               true,
	"HOMEPATH":                true,
}

// Config specifies options for environment sanitization.
type Config struct {
	VirtualHome        string   // Path to ephemeral virtual $HOME directory
	ScratchDir         string   // Path to ephemeral scratch space ($TMPDIR)
	StagingCache       string   // Path to isolated cache staging directory
	ProxyURL           string   // Optional proxy URL, e.g. "http://127.0.0.1:18443"
	DNSResolverAddress string   // Optional in-process DNS interceptor address, e.g. "127.0.0.1:5353"
	KeepEnv            []string // Additional variables explicitly allowed by user
	DenyEnv            []string // Variables explicitly denied / scrubbed
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

// BuildCleanEnvironment constructs a sanitized, deduplicated environment slice for sandboxed execution.
func BuildCleanEnvironment(cfg Config, hostEnv []string) []string {
	return NewSanitizer(cfg).Sanitize(hostEnv)
}

// Sanitize filters host environment variables, purges unsafe relative entries from PATH,
// injects virtual paths, deduplicates keys, and exports the nesting sentinel __AIRLOCK_ACTIVE=1.
func (s *DefaultSanitizer) Sanitize(hostEnv []string) []string {
	denySet := make(map[string]bool, len(s.config.DenyEnv))
	for _, d := range s.config.DenyEnv {
		trimmed := strings.TrimSpace(d)
		if trimmed != "" {
			denySet[trimmed] = true
			if runtime.GOOS == "windows" {
				denySet[strings.ToUpper(trimmed)] = true
			}
		}
	}

	keepSet := make(map[string]bool, len(s.config.KeepEnv))
	for _, k := range s.config.KeepEnv {
		trimmed := strings.TrimSpace(k)
		if trimmed != "" && !denySet[trimmed] && !(runtime.GOOS == "windows" && denySet[strings.ToUpper(trimmed)]) {
			keepSet[trimmed] = true
		}
	}

	type kvPair struct {
		key string
		val string
	}
	order := make([]string, 0, len(hostEnv)+24)
	entries := make(map[string]kvPair, len(hostEnv)+24)

	canonicalKey := func(k string) string {
		if runtime.GOOS == "windows" {
			return strings.ToUpper(k)
		}
		return k
	}

	setEnv := func(key, val string) {
		ck := canonicalKey(key)
		if _, exists := entries[ck]; !exists {
			order = append(order, ck)
		}
		entries[ck] = kvPair{key: key, val: val}
	}

	for _, entry := range hostEnv {
		idx := strings.Index(entry, "=")
		if idx == -1 {
			continue
		}
		key := entry[:idx]
		val := entry[idx+1:]
		keyUpper := strings.ToUpper(key)

		// Never inherit untrusted nesting sentinel from caller environment (AIR-03)
		if keyUpper == "__AIRLOCK_ACTIVE" {
			continue
		}

		// Explicit deny list takes absolute priority
		if denySet[key] || (runtime.GOOS == "windows" && denySet[keyUpper]) {
			continue
		}

		// Block GIT_CONFIG_* injection unless explicitly requested via KeepEnv (AIR-08)
		if strings.HasPrefix(keyUpper, "GIT_CONFIG_") && !keepSet[key] {
			continue
		}

		// Explicit keep-env overrides take precedence
		if keepSet[key] || (runtime.GOOS == "windows" && keepSet[keyUpper]) {
			if keyUpper == "PATH" {
				val = SanitizePath(val)
			}
			setEnv(key, val)
			continue
		}

		// Drop variables not on the allowlist (e.g. AWS_*, DATABASE_URL, GITHUB_TOKEN)
		if !SafeEnvAllowlist[key] && !SafeEnvAllowlist[keyUpper] {
			continue
		}

		// Sanitize PATH to eliminate relative trojan binaries
		if keyUpper == "PATH" {
			val = SanitizePath(val)
		}

		// HOME, USERPROFILE, TMPDIR, TEMP, TMP are overridden with virtual paths below
		if keyUpper == "HOME" || keyUpper == "TMPDIR" || keyUpper == "USERPROFILE" || keyUpper == "TEMP" || keyUpper == "TMP" {
			continue
		}

		setEnv(key, val)
	}

	// Inject virtual paths
	if s.config.VirtualHome != "" {
		setEnv("HOME", s.config.VirtualHome)
		if runtime.GOOS == "windows" {
			setEnv("USERPROFILE", s.config.VirtualHome)
		}
	}
	if s.config.ScratchDir != "" {
		setEnv("TMPDIR", s.config.ScratchDir)
		if runtime.GOOS == "windows" {
			setEnv("TEMP", s.config.ScratchDir)
			setEnv("TMP", s.config.ScratchDir)
		}
	}

	// Inject cache redirects to ephemeral staging layer (V-12, AIR-08: overwrites inherited GOCACHE/GOMODCACHE)
	if s.config.StagingCache != "" {
		setEnv("npm_config_cache", filepath.Join(s.config.StagingCache, "npm"))
		setEnv("YARN_CACHE_FOLDER", filepath.Join(s.config.StagingCache, "yarn"))
		setEnv("PIP_CACHE_DIR", filepath.Join(s.config.StagingCache, "pip"))
		setEnv("UV_CACHE_DIR", filepath.Join(s.config.StagingCache, "uv"))
		setEnv("CARGO_TARGET_DIR", filepath.Join(s.config.StagingCache, "cargo-target"))
		setEnv("GOCACHE", filepath.Join(s.config.StagingCache, "go-build"))
		setEnv("GOMODCACHE", filepath.Join(s.config.StagingCache, "go-mod"))
		setEnv("pnpm_config_store_dir", filepath.Join(s.config.StagingCache, "pnpm-store"))
		setEnv("pnpm_config_cache_dir", filepath.Join(s.config.StagingCache, "pnpm-cache"))
		setEnv("PNPM_HOME", filepath.Join(s.config.StagingCache, "pnpm-home"))
		setEnv("GRADLE_USER_HOME", filepath.Join(s.config.StagingCache, "gradle"))
		setEnv("MAVEN_OPTS", "-Dmaven.repo.local="+filepath.Join(s.config.StagingCache, "m2", "repository"))
		setEnv("NUGET_PACKAGES", filepath.Join(s.config.StagingCache, "nuget", "packages"))
		setEnv("DOTNET_CLI_HOME", filepath.Join(s.config.StagingCache, "dotnet"))
		setEnv("GEM_HOME", filepath.Join(s.config.StagingCache, "gem"))
		setEnv("BUNDLE_PATH", filepath.Join(s.config.StagingCache, "bundle"))
		setEnv("SWIFTPM_CACHE_DIR", filepath.Join(s.config.StagingCache, "swiftpm"))
		setEnv("CP_CACHE_DIR", filepath.Join(s.config.StagingCache, "cocoapods"))
		setEnv("HELM_CACHE_HOME", filepath.Join(s.config.StagingCache, "helm"))
	}

	// Inject proxy configuration if active
	if s.config.ProxyURL != "" {
		setEnv("HTTP_PROXY", s.config.ProxyURL)
		setEnv("HTTPS_PROXY", s.config.ProxyURL)
		setEnv("http_proxy", s.config.ProxyURL)
		setEnv("https_proxy", s.config.ProxyURL)
		setEnv("npm_config_proxy", s.config.ProxyURL)
		setEnv("PIP_PROXY", s.config.ProxyURL)
	}

	// Inject DNS interceptor address for tools that honour it
	if s.config.DNSResolverAddress != "" {
		setEnv("AIRLOCK_DNS", s.config.DNSResolverAddress)
	}

	// Inject TLS root certificate fallbacks for sandboxed runtimes (e.g. macOS Seatbelt blocking securityd)
	if _, hasSSLCert := entries[canonicalKey("SSL_CERT_FILE")]; !hasSSLCert && !denySet["SSL_CERT_FILE"] {
		if _, err := os.Stat("/etc/ssl/cert.pem"); err == nil {
			setEnv("SSL_CERT_FILE", "/etc/ssl/cert.pem")
		}
	}
	if _, hasGODEBUG := entries[canonicalKey("GODEBUG")]; !hasGODEBUG && !denySet["GODEBUG"] {
		setEnv("GODEBUG", "x509usefallbackroots=1")
	}

	// Export nesting sentinel to prevent recursive sandboxing crashes in agent loops
	setEnv("__AIRLOCK_ACTIVE", "1")

	result := make([]string, 0, len(order))
	for _, ck := range order {
		pair := entries[ck]
		result = append(result, pair.key+"="+pair.val)
	}

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
		if clean == "/" || clean == "\\" || clean == "." {
			continue
		}
		// On Windows, single drive root like "C:\"
		if len(clean) <= 3 && strings.HasSuffix(clean, ":\\") {
			continue
		}

		// Strip .airlock/bin to prevent child processes from calling back into shims
		if strings.HasSuffix(clean, filepath.Join(".airlock", "bin")) {
			continue
		}

		cleanEntries = append(cleanEntries, clean)
	}

	return strings.Join(cleanEntries, string(os.PathListSeparator))
}
