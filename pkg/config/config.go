// Package config provides declarative project policy management and invariant security guardrails.
package config

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"gopkg.in/yaml.v3"
)

// Mode defines the confinement policy mode.
type Mode string

const (
	ModeStrict     Mode = "strict"
	ModePermissive Mode = "permissive"
	ModeAudit      Mode = "audit"
)

// Config represents the top-level declarative policy configuration for Airlock.
type Config struct {
	Version     string            `yaml:"version" json:"version"`
	Mode        Mode              `yaml:"mode" json:"mode"`
	Network     NetworkConfig     `yaml:"network" json:"network"`
	Env         EnvConfig         `yaml:"env" json:"env"`
	Filesystem  FilesystemConfig  `yaml:"filesystem" json:"filesystem"`
	Vetting     VettingConfig     `yaml:"vetting" json:"vetting"`
	Interactive InteractiveConfig `yaml:"interactive" json:"interactive"`
}

// NetworkConfig defines outbound network egress policy.
type NetworkConfig struct {
	Airgap              bool     `yaml:"airgap" json:"airgap"`
	AllowDomains        []string `yaml:"allow_domains" json:"allow_domains"`
	UnknownDomainAction string   `yaml:"unknown_domain_action" json:"unknown_domain_action"` // "prompt", "nxdomain", "refused"
}

// EnvConfig defines environment variable pass-through rules.
type EnvConfig struct {
	Allow []string `yaml:"allow" json:"allow"`
	Deny  []string `yaml:"deny" json:"deny"`
}

// FilesystemConfig defines filesystem read/write boundary overrides and secret masks.
type FilesystemConfig struct {
	AllowRead  []string `yaml:"allow_read" json:"allow_read"`
	AllowWrite []string `yaml:"allow_write" json:"allow_write"`
	DenyRead   []string `yaml:"deny_read" json:"deny_read"`
	DenyWrite  []string `yaml:"deny_write" json:"deny_write"`
}

// VettingConfig defines Argus static analysis options.
type VettingConfig struct {
	Enable       bool     `yaml:"enable" json:"enable"`
	Strict       bool     `yaml:"strict" json:"strict"`
	IgnoredRules []string `yaml:"ignored_rules" json:"ignored_rules"`
}

// InteractiveConfig defines real-time dynamic capability prompt options.
type InteractiveConfig struct {
	PromptOnUnknownDomain bool `yaml:"prompt_on_unknown_domain" json:"prompt_on_unknown_domain"`
	PromptTimeoutSec      int  `yaml:"prompt_timeout_sec" json:"prompt_timeout_sec"`
}

// ValidationIssue represents a warning or error discovered during config validation.
type ValidationIssue struct {
	Field    string
	Severity string // "ERROR", "WARNING", "INFO"
	Message  string
}

// DefaultConfig returns the baseline hardened configuration.
func DefaultConfig() *Config {
	return &Config{
		Version: "1",
		Mode:    ModeStrict,
		Network: NetworkConfig{
			Airgap:              false,
			AllowDomains:        []string{},
			UnknownDomainAction: "prompt",
		},
		Env: EnvConfig{
			Allow: []string{},
			Deny:  []string{},
		},
		Filesystem: FilesystemConfig{
			AllowRead:  []string{},
			AllowWrite: []string{},
			DenyRead:   []string{},
			DenyWrite:  []string{},
		},
		Vetting: VettingConfig{
			Enable:       false,
			Strict:       false,
			IgnoredRules: []string{},
		},
		Interactive: InteractiveConfig{
			PromptOnUnknownDomain: true,
			PromptTimeoutSec:      15,
		},
	}
}

// ConfigFileNames lists the standard policy file names searched in a repository.
var ConfigFileNames = []string{
	"airlock.yaml",
	".airlock.yaml",
	"airlock.yml",
	".airlock.yml",
	"airlock.json",
	".airlock.json",
	".airlockrc",
}

// Default returns the baseline hardened configuration (alias for DefaultConfig).
func Default() *Config {
	return DefaultConfig()
}

// DiscoverConfig searches for an airlock policy file starting at workspaceRoot.
// It returns the path to the found file, the parsed and sanitized Config, or nil if none found.
func DiscoverConfig(workspaceRoot string) (string, *Config, error) {
	p, cfg, _, err := DiscoverConfigWithIssues(workspaceRoot)
	return p, cfg, err
}

// DiscoverConfigWithIssues searches for an airlock policy file starting at workspaceRoot.
// It returns the path to the found file, the parsed Config, any validation issues detected, or an error.
func DiscoverConfigWithIssues(workspaceRoot string) (string, *Config, []ValidationIssue, error) {
	if workspaceRoot != "" {
		for _, name := range ConfigFileNames {
			p := filepath.Join(workspaceRoot, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				cfg, issues, err := LoadFromFileWithIssues(p)
				return p, cfg, issues, err
			}
		}
	}

	// Check global config at ~/.airlock/config.yaml
	home, err := os.UserHomeDir()
	if err == nil {
		globalPath := filepath.Join(home, ".airlock", "config.yaml")
		if fi, err := os.Stat(globalPath); err == nil && !fi.IsDir() {
			cfg, issues, err := LoadFromFileWithIssues(globalPath)
			return globalPath, cfg, issues, err
		}
	}

	return "", nil, nil, nil
}

// LoadFromFile reads, parses, and sanitizes a policy configuration file.
func LoadFromFile(path string) (*Config, error) {
	cfg, _, err := LoadFromFileWithIssues(path)
	return cfg, err
}

// LoadFromFileWithIssues reads and parses a policy configuration file and returns any guardrail issues detected.
func LoadFromFileWithIssues(path string) (*Config, []ValidationIssue, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, fmt.Errorf("read config file %q: %w", path, err)
	}

	cfg := DefaultConfig()

	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" || (ext == "" && strings.HasSuffix(filepath.Base(path), ".airlockrc")) {
		if err := json.Unmarshal(data, cfg); err != nil {
			// Try YAML fallback if JSON parsing fails
			if yamlErr := yaml.Unmarshal(data, cfg); yamlErr != nil {
				return nil, nil, fmt.Errorf("parse json config %q: %w", path, err)
			}
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, nil, fmt.Errorf("parse yaml config %q: %w", path, err)
		}
	}

	// Sanitize and enforce invariants
	issues := SanitizeAndEnforceGuardrails(cfg)

	return cfg, issues, nil
}

// ForbiddenPathsRegex or substrings that cannot be granted access via declarative config.
var forbiddenPathPatterns = []string{
	".ssh",
	".aws",
	".gnupg",
	".kube",
	".config/gcloud",
	"docker.sock",
	"/var/run/docker.sock",
	".git",
}

// SanitizeAndEnforceGuardrails strips any dangerous permissions attempted in an untrusted config.
func SanitizeAndEnforceGuardrails(cfg *Config) []ValidationIssue {
	var issues []ValidationIssue

	if cfg == nil {
		return issues
	}

	// 1. Filesystem allow_read guardrails
	var sanitizedAllowRead []string
	for _, p := range cfg.Filesystem.AllowRead {
		if isForbiddenPath(p) {
			issues = append(issues, ValidationIssue{
				Field:    "filesystem.allow_read",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Forbidden path override %q stripped due to core security invariants (V-01/V-06).", p),
			})
		} else {
			sanitizedAllowRead = append(sanitizedAllowRead, p)
		}
	}
	cfg.Filesystem.AllowRead = sanitizedAllowRead

	// 2. Filesystem allow_write guardrails
	var sanitizedAllowWrite []string
	for _, p := range cfg.Filesystem.AllowWrite {
		if isForbiddenPath(p) {
			issues = append(issues, ValidationIssue{
				Field:    "filesystem.allow_write",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Forbidden path override %q stripped due to core security invariants (V-01/V-03/V-06).", p),
			})
		} else {
			sanitizedAllowWrite = append(sanitizedAllowWrite, p)
		}
	}
	cfg.Filesystem.AllowWrite = sanitizedAllowWrite

	// 3. Environment allow guardrails (cannot allow core dangerous injection vectors)
	var sanitizedEnvAllow []string
	for _, e := range cfg.Env.Allow {
		if IsForbiddenEnv(e) {
			issues = append(issues, ValidationIssue{
				Field:    "env.allow",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Dangerous dynamic linker injection variable %q stripped from env allowlist.", e),
			})
		} else {
			sanitizedEnvAllow = append(sanitizedEnvAllow, e)
		}
	}
	cfg.Env.Allow = sanitizedEnvAllow

	return issues
}

// IsForbiddenEnv checks if an environment variable is restricted by core security guardrails.
func IsForbiddenEnv(e string) bool {
	upper := strings.ToUpper(strings.TrimSpace(e))
	return upper == "LD_PRELOAD" || upper == "DYLD_INSERT_LIBRARIES" || upper == "DYLD_FORCE_FLAT_NAMESPACE"
}

// IsForbiddenPath checks if a path targets sensitive secrets or restricted system files.
func IsForbiddenPath(p string) bool {
	return isForbiddenPath(p)
}

func isForbiddenPath(p string) bool {
	normalized := strings.ReplaceAll(p, "\\", "/")
	normalized = strings.TrimPrefix(normalized, "~/")
	normalized = strings.TrimPrefix(normalized, "$HOME/")

	parts := strings.Split(normalized, "/")
	for _, pattern := range forbiddenPathPatterns {
		if strings.Contains(normalized, pattern) {
			return true
		}
		for _, part := range parts {
			if part == pattern {
				return true
			}
		}
	}
	return false
}

// MatchDomain evaluates whether a requested hostname matches an allowed domain rule.
// It supports exact matches ("registry.npmjs.org"), subdomains ("sub.example.com" for "example.com"),
// and wildcard patterns ("*.github.com", "*.internal.corp").
func MatchDomain(rule, host string) bool {
	rule = strings.ToLower(strings.TrimSpace(rule))
	host = strings.ToLower(strings.TrimSpace(host))

	if rule == "" || host == "" {
		return false
	}

	// Strip trailing port if present in host
	if idx := strings.Index(host, ":"); idx != -1 {
		host = host[:idx]
	}

	// Exact match
	if rule == host {
		return true
	}

	// Wildcard root match (e.g., rule is "*.example.com" and host is "example.com")
	if strings.HasPrefix(rule, "*.") && host == rule[2:] {
		return true
	}

	// Subdomain match (e.g. host is "sub.example.com" and rule is "example.com" or "*.example.com")
	baseRule := strings.TrimPrefix(rule, "*.")
	if strings.HasSuffix(host, "."+baseRule) {
		return true
	}

	return false
}

// MatchAnyDomain checks if host matches any of the domain patterns.
func MatchAnyDomain(rules []string, host string) bool {
	for _, rule := range rules {
		if MatchDomain(rule, host) {
			return true
		}
	}
	return false
}

// AppendAllowedDomain opens the policy file at path (or creates one) and appends the domain to allow_domains.
func AppendAllowedDomain(path string, domain string) error {
	domain = strings.TrimSpace(domain)
	if domain == "" {
		return nil
	}

	var cfg *Config
	if _, err := os.Stat(path); err == nil {
		var err error
		cfg, err = LoadFromFile(path)
		if err != nil {
			return err
		}
	} else {
		cfg = DefaultConfig()
	}

	// Check if already present
	for _, d := range cfg.Network.AllowDomains {
		if strings.EqualFold(d, domain) {
			return nil // already exists
		}
	}

	cfg.Network.AllowDomains = append(cfg.Network.AllowDomains, domain)

	data, err := yaml.Marshal(cfg)
	if err != nil {
		return fmt.Errorf("marshal updated config: %w", err)
	}

	if err := os.WriteFile(path, data, 0644); err != nil {
		return fmt.Errorf("write updated config %q: %w", path, err)
	}

	return nil
}

// GenerateTemplate generates a documented airlock.yaml template for the given project type.
func GenerateTemplate(projectType string) string {
	var specificDomains []string
	var specificEnv []string
	var comment string

	switch strings.ToLower(projectType) {
	case "node", "javascript", "typescript":
		comment = "# Airlock Policy — Node.js / TypeScript Workspace"
		specificDomains = []string{"registry.npmjs.org", "registry.yarnpkg.com"}
		specificEnv = []string{"NODE_ENV", "NPM_CONFIG_REGISTRY"}
	case "python":
		comment = "# Airlock Policy — Python Workspace"
		specificDomains = []string{"pypi.org", "files.pythonhosted.org"}
		specificEnv = []string{"PIP_INDEX_URL", "PYTHONUNBUFFERED"}
	case "rust":
		comment = "# Airlock Policy — Rust / Cargo Workspace"
		specificDomains = []string{"crates.io", "static.crates.io", "github.com"}
		specificEnv = []string{"RUST_LOG", "CARGO_HOME"}
	case "go", "golang":
		comment = "# Airlock Policy — Go Workspace"
		specificDomains = []string{"proxy.golang.org", "sum.golang.org", "github.com"}
		specificEnv = []string{"GOPROXY", "GOSUMDB", "GOPRIVATE"}
	default:
		comment = "# Airlock Policy — General Workspace"
		specificDomains = []string{"registry.npmjs.org", "pypi.org", "crates.io"}
		specificEnv = []string{"CI"}
	}

	var sb strings.Builder
	sb.WriteString(comment + "\n")
	sb.WriteString("version: \"1\"\n\n")
	sb.WriteString("# Confinement strictness mode: strict (fail-closed), permissive (prompt on unknown), audit (log-only)\n")
	sb.WriteString("mode: strict\n\n")
	sb.WriteString("network:\n")
	sb.WriteString("  # Set to true for complete offline airgap isolation\n")
	sb.WriteString("  airgap: false\n")
	sb.WriteString("  # Permitted domain endpoints (supports wildcards e.g. *.mycorp.com)\n")
	sb.WriteString("  allow_domains:\n")
	for _, d := range specificDomains {
		sb.WriteString(fmt.Sprintf("    - %q\n", d))
	}
	sb.WriteString("  # Action for unrecognized domain requests: prompt | nxdomain | refused\n")
	sb.WriteString("  unknown_domain_action: prompt\n\n")
	sb.WriteString("env:\n")
	sb.WriteString("  # Additional environment variables passed into the sandbox\n")
	sb.WriteString("  allow:\n")
	for _, e := range specificEnv {
		sb.WriteString(fmt.Sprintf("    - %q\n", e))
	}
	sb.WriteString("  # Explicitly scrubbed sensitive variables\n")
	sb.WriteString("  deny:\n")
	sb.WriteString("    - \"DATABASE_URL\"\n")
	sb.WriteString("    - \"AWS_SECRET_ACCESS_KEY\"\n\n")
	sb.WriteString("filesystem:\n")
	sb.WriteString("  # Additional read-only host paths required by tooling\n")
	sb.WriteString("  allow_read: []\n")
	sb.WriteString("  # Additional scratch/temp writable directories\n")
	sb.WriteString("  allow_write: []\n")
	sb.WriteString("  # Extra secret patterns masked inside workspace root\n")
	sb.WriteString("  deny_read: []\n\n")
	sb.WriteString("vetting:\n")
	sb.WriteString("  # Run Argus static analysis heuristics before sandboxed execution\n")
	sb.WriteString("  enable: true\n")
	sb.WriteString("  strict: false\n")
	sb.WriteString("  ignored_rules: []\n\n")
	sb.WriteString("interactive:\n")
	sb.WriteString("  # Prompt user on terminal for runtime permission when unknown domain is requested\n")
	sb.WriteString("  prompt_on_unknown_domain: true\n")
	sb.WriteString("  prompt_timeout_sec: 15\n")

	return sb.String()
}
