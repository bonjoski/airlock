package config

import (
	"fmt"
	"strings"
)

// Standard Profile Names
const (
	ProfileAgent   = "agent"
	ProfileDefault = "default"
	ProfileStrict  = "strict"
	ProfileAirgap  = "airgap"
)

// AgentDefaultAllowDomains lists the essential registries and AI model endpoints
// required for autonomous coding assistants (Claude Code, Cursor, OpenCode, Aider).
var AgentDefaultAllowDomains = []string{
	"api.anthropic.com",
	"api.openai.com",
	"generativelanguage.googleapis.com",
	"registry.npmjs.org",
	"registry.yarnpkg.com",
	"pypi.org",
	"files.pythonhosted.org",
	"proxy.golang.org",
	"crates.io",
	"static.crates.io",
	"github.com",
	"api.github.com",
}

// AgentDefaultDenyPaths defines forbidden host credential directories.
var AgentDefaultDenyPaths = []string{
	"~/.ssh",
	"~/.aws",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gcloud",
	"/var/run/docker.sock",
	".env",
	".env.*",
}

// AgentDefaultSecrets lists credentials dynamically leased via Locksmith ETX.
var AgentDefaultSecrets = []string{
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"GITHUB_TOKEN",
	"GEMINI_API_KEY",
}

// GetBuiltinProfile constructs a pre-configured, hardened policy for known execution profiles.
func GetBuiltinProfile(name string) (*Config, error) {
	norm := strings.ToLower(strings.TrimSpace(name))
	switch norm {
	case "", ProfileDefault:
		return DefaultConfig(), nil

	case ProfileStrict:
		cfg := DefaultConfig()
		cfg.Mode = ModeStrict
		cfg.Vetting.Enable = true
		cfg.Vetting.Strict = true
		return cfg, nil

	case ProfileAirgap:
		cfg := DefaultConfig()
		cfg.Network.Airgap = true
		return cfg, nil

	case ProfileAgent:
		cfg := DefaultConfig()
		cfg.Version = "1"
		cfg.Mode = ModeStrict

		// 1. Network: Pinned AI endpoints and package registries only
		cfg.Network.Airgap = false
		cfg.Network.AllowDomains = make([]string, len(AgentDefaultAllowDomains))
		copy(cfg.Network.AllowDomains, AgentDefaultAllowDomains)
		cfg.Network.UnknownDomainAction = "refused"

		// 2. Filesystem: Explicit boundary blocks for credentials and metadata
		cfg.Filesystem.DenyRead = make([]string, len(AgentDefaultDenyPaths))
		copy(cfg.Filesystem.DenyRead, AgentDefaultDenyPaths)
		cfg.Filesystem.DenyWrite = append(cfg.Filesystem.DenyRead, ".git")

		// 3. Static Analysis: Mandatory pre-execution AST inspection via Argus
		cfg.Vetting.Enable = true
		cfg.Vetting.Strict = true

		// 4. Interactive: Non-interactive fail-closed defaults for autonomous loops
		cfg.Interactive.PromptOnUnknownDomain = false
		cfg.Interactive.PromptTimeoutSec = 5

		return cfg, nil

	default:
		return nil, fmt.Errorf("unknown execution profile %q (available: agent, strict, airgap, default)", name)
	}
}

// MergeProfiles overlays a custom policy on top of a base profile.
func MergeProfiles(base *Config, overlay *Config) *Config {
	if base == nil {
		return overlay
	}
	if overlay == nil {
		return base
	}

	merged := *base

	if overlay.Mode != "" {
		merged.Mode = overlay.Mode
	}
	if overlay.Network.Airgap {
		merged.Network.Airgap = true
	}
	if len(overlay.Network.AllowDomains) > 0 {
		merged.Network.AllowDomains = append(merged.Network.AllowDomains, overlay.Network.AllowDomains...)
	}
	if overlay.Network.UnknownDomainAction != "" {
		merged.Network.UnknownDomainAction = overlay.Network.UnknownDomainAction
	}

	if len(overlay.Env.Allow) > 0 {
		merged.Env.Allow = append(merged.Env.Allow, overlay.Env.Allow...)
	}
	if len(overlay.Env.Deny) > 0 {
		merged.Env.Deny = append(merged.Env.Deny, overlay.Env.Deny...)
	}

	if len(overlay.Filesystem.AllowRead) > 0 {
		merged.Filesystem.AllowRead = append(merged.Filesystem.AllowRead, overlay.Filesystem.AllowRead...)
	}
	if len(overlay.Filesystem.AllowWrite) > 0 {
		merged.Filesystem.AllowWrite = append(merged.Filesystem.AllowWrite, overlay.Filesystem.AllowWrite...)
	}
	if len(overlay.Filesystem.DenyRead) > 0 {
		merged.Filesystem.DenyRead = append(merged.Filesystem.DenyRead, overlay.Filesystem.DenyRead...)
	}
	if len(overlay.Filesystem.DenyWrite) > 0 {
		merged.Filesystem.DenyWrite = append(merged.Filesystem.DenyWrite, overlay.Filesystem.DenyWrite...)
	}

	if overlay.Vetting.Enable {
		merged.Vetting.Enable = true
	}
	if overlay.Vetting.Strict {
		merged.Vetting.Strict = true
	}

	return &merged
}
