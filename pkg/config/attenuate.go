package config

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// IsValidDomainRule returns true if rule is a syntactically safe hostname or subdomain wildcard
// and NOT a bare TLD or catch-all wildcard (e.g. "*", "com", ".com", "*.com") (AIR-02).
func IsValidDomainRule(rule string) bool {
	r := strings.ToLower(strings.TrimSpace(rule))
	if r == "" || r == "*" || r == "." {
		return false
	}
	if idx := strings.Index(r, ":"); idx != -1 {
		r = r[:idx]
	}
	r = strings.TrimSuffix(r, ".")
	if r == "localhost" {
		return true
	}

	base := r
	if strings.HasPrefix(base, "*.") {
		base = base[2:]
	} else if strings.HasPrefix(base, ".") {
		// Reject leading-dot bare TLD wildcards like ".com"
		return false
	}

	if strings.Contains(base, "*") {
		return false
	}

	// Require at least two non-empty labels (e.g. "example.com") for all non-localhost patterns
	labels := strings.Split(base, ".")
	if len(labels) < 2 {
		return false
	}
	for _, lbl := range labels {
		if strings.TrimSpace(lbl) == "" {
			return false
		}
	}
	return true
}

// IsPathWithinWorkspace verifies that candidate resolves strictly inside workspaceRoot
// without home-directory expansion or forbidden path patterns (AIR-02).
func IsPathWithinWorkspace(candidate, workspaceRoot string) bool {
	cleaned := strings.TrimSpace(candidate)
	if cleaned == "" || workspaceRoot == "" {
		return false
	}
	if strings.HasPrefix(cleaned, "~") || strings.Contains(cleaned, "$HOME") {
		return false
	}
	if isForbiddenPath(cleaned) {
		return false
	}

	wsClean := filepath.Clean(workspaceRoot)
	if resolvedWs, err := filepath.EvalSymlinks(wsClean); err == nil && resolvedWs != "" {
		wsClean = resolvedWs
	}

	var target string
	if filepath.IsAbs(cleaned) {
		target = filepath.Clean(cleaned)
	} else {
		target = filepath.Clean(filepath.Join(wsClean, cleaned))
	}
	if resolvedTarget, err := filepath.EvalSymlinks(target); err == nil && resolvedTarget != "" {
		target = resolvedTarget
	}

	if target == wsClean {
		return true
	}
	prefix := wsClean
	if !strings.HasSuffix(prefix, string(filepath.Separator)) {
		prefix += string(filepath.Separator)
	}
	return strings.HasPrefix(target, prefix)
}

// IsUntrustedWorkspaceConfigPath returns true when configPath resides inside workspaceRoot
// (as opposed to user ~/.airlock/config.yaml, ~/.config/airlock/config.yaml, or an external --config).
func IsUntrustedWorkspaceConfigPath(configPath, workspaceRoot string) bool {
	if configPath == "" || workspaceRoot == "" {
		return false
	}
	absCfg, err := filepath.Abs(configPath)
	if err != nil {
		return true
	}
	absWs, err := filepath.Abs(workspaceRoot)
	if err != nil {
		return true
	}
	if resolvedCfg, err := filepath.EvalSymlinks(absCfg); err == nil && resolvedCfg != "" {
		absCfg = resolvedCfg
	}
	if resolvedWs, err := filepath.EvalSymlinks(absWs); err == nil && resolvedWs != "" {
		absWs = resolvedWs
	}

	// Never treat ~/.airlock or ~/.config/airlock as untrusted unless workspaceRoot IS that dir
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		if resolvedHome, err := filepath.EvalSymlinks(home); err == nil && resolvedHome != "" {
			home = resolvedHome
		}
		userDirs := []string{
			filepath.Join(home, ".airlock"),
			filepath.Join(home, ".config", "airlock"),
		}
		for _, ud := range userDirs {
			udPrefix := ud + string(filepath.Separator)
			if strings.HasPrefix(absCfg, udPrefix) && absWs != ud && !strings.HasPrefix(absWs, udPrefix) {
				return false
			}
		}
	}

	if absCfg == absWs {
		return true
	}
	wsPrefix := absWs
	if !strings.HasSuffix(wsPrefix, string(filepath.Separator)) {
		wsPrefix += string(filepath.Separator)
	}
	return strings.HasPrefix(absCfg, wsPrefix)
}

// DiscoverAndMergeConfig loads user-level config (if any) as trusted overlay on base,
// and monotonically attenuates any discovered workspace-local .airlock.yaml on top (AIR-02).
func DiscoverAndMergeConfig(base *Config, workspaceRoot string) (string, *Config, []ValidationIssue, error) {
	effective := cloneConfig(base)
	var allIssues []ValidationIssue
	var selectedPath string

	if home, err := os.UserHomeDir(); err == nil && home != "" {
		candidates := []string{
			filepath.Join(home, ".config", "airlock", "config.yaml"),
			filepath.Join(home, ".airlock", "config.yaml"),
		}
		for _, gp := range candidates {
			if fi, err := os.Stat(gp); err == nil && !fi.IsDir() {
				gCfg, gIss, loadErr := LoadFromFileWithIssues(gp)
				if loadErr != nil {
					return gp, nil, nil, loadErr
				}
				if base != nil {
					effective = MergeProfiles(effective, gCfg)
				} else {
					effective = gCfg
				}
				allIssues = append(allIssues, gIss...)
				selectedPath = gp
				break
			}
		}
	}

	if workspaceRoot != "" {
		for _, name := range ConfigFileNames {
			p := filepath.Join(workspaceRoot, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				wsCfg, wsIss, loadErr := LoadFromFileWithIssues(p)
				if loadErr != nil {
					return p, nil, nil, loadErr
				}
				attenuated, attIss := AttenuateWorkspaceConfig(effective, wsCfg, workspaceRoot)
				allIssues = append(allIssues, wsIss...)
				allIssues = append(allIssues, attIss...)
				return p, attenuated, allIssues, nil
			}
		}
	}

	if selectedPath == "" && base == nil {
		return "", nil, nil, nil
	}
	return selectedPath, effective, allIssues, nil
}

// AttenuateWorkspaceConfig enforces monotonic security attenuation when merging an
// untrusted repository-local .airlock.yaml on top of a baseline configuration (AIR-02).
//
// Invariants enforced:
//  1. Never adds filesystem.allow_write or filesystem.allow_read paths outside workspaceRoot.
//  2. Never adds env.allow host secret variables.
//  3. Never populates vetting.ignored_rules or weakens vetting/mode settings.
//  4. Never adds network.allowed_unix_sockets or network.allowed_loopback_ports.
//  5. May only narrow network.allow_domains (set intersection) and add deny_* / airgap / anti_loopback rules.
func AttenuateWorkspaceConfig(base *Config, untrusted *Config, workspaceRoot string) (*Config, []ValidationIssue) {
	var issues []ValidationIssue

	if base == nil {
		base = DefaultConfig()
	}
	out := cloneConfig(base)
	if untrusted == nil {
		return out, issues
	}

	issues = append(issues, SanitizeAndEnforceGuardrails(untrusted)...)

	// 1. Mode: only allow tightening to ModeStrict, never weakening to permissive/audit
	if untrusted.Mode != "" && untrusted.Mode != ModeStrict && out.Mode == ModeStrict {
		issues = append(issues, ValidationIssue{
			Field:    "mode",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Workspace config attempted to weaken mode to %q; retaining strict mode (AIR-02).", untrusted.Mode),
		})
	} else if untrusted.Mode == ModeStrict {
		out.Mode = ModeStrict
	}

	// 2. Network booleans: monotonic tightening only
	if untrusted.Network.Airgap {
		out.Network.Airgap = true
	}
	if untrusted.Network.AntiLoopback {
		out.Network.AntiLoopback = true
	}
	if untrusted.Network.UnknownDomainAction == "refused" || untrusted.Network.UnknownDomainAction == "nxdomain" {
		out.Network.UnknownDomainAction = untrusted.Network.UnknownDomainAction
	}

	// Reject workspace attempts to punch holes in loopback or Unix sockets
	if len(untrusted.Network.AllowedUnixSockets) > 0 {
		issues = append(issues, ValidationIssue{
			Field:    "network.allowed_unix_sockets",
			Severity: "WARNING",
			Message:  "Workspace config cannot whitelist host Unix sockets (AIR-02).",
		})
	}
	if len(untrusted.Network.AllowedLoopbackPorts) > 0 {
		issues = append(issues, ValidationIssue{
			Field:    "network.allowed_loopback_ports",
			Severity: "WARNING",
			Message:  "Workspace config cannot whitelist host loopback ports (AIR-02).",
		})
	}

	// 3. Domain allowlist: only narrow (intersect) against ceiling; never expand
	if len(untrusted.Network.AllowDomains) > 0 {
		ceiling := out.Network.AllowDomains
		hasExplicitCeiling := len(ceiling) > 0
		if !hasExplicitCeiling {
			ceiling = StandardDefaultAllowDomains
		}

		var narrowed []string
		for _, d := range untrusted.Network.AllowDomains {
			trimmed := strings.ToLower(strings.TrimSpace(d))
			if !IsValidDomainRule(trimmed) {
				issues = append(issues, ValidationIssue{
					Field:    "network.allow_domains",
					Severity: "WARNING",
					Message:  fmt.Sprintf("Invalid or bare-TLD domain pattern %q stripped from workspace config (AIR-02).", d),
				})
				continue
			}
			probeHost := strings.TrimPrefix(trimmed, "*.")
			if MatchAnyDomain(ceiling, probeHost) {
				narrowed = append(narrowed, trimmed)
			} else {
				issues = append(issues, ValidationIssue{
					Field:    "network.allow_domains",
					Severity: "WARNING",
					Message:  fmt.Sprintf("Workspace config cannot expand allow_domains with %q outside base profile ceiling (AIR-02).", d),
				})
			}
		}
		if hasExplicitCeiling || len(narrowed) > 0 {
			out.Network.AllowDomains = narrowed
		}
	}

	// 4. Environment: workspace config MUST NEVER add env.allow; may only add env.deny
	if len(untrusted.Env.Allow) > 0 {
		issues = append(issues, ValidationIssue{
			Field:    "env.allow",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Workspace config attempted to pass %d host env vars (%v); stripped by monotonic attenuation (AIR-02).", len(untrusted.Env.Allow), untrusted.Env.Allow),
		})
	}
	if len(untrusted.Env.Deny) > 0 {
		out.Env.Deny = appendUnique(out.Env.Deny, untrusted.Env.Deny...)
	}

	// 5. Filesystem: allow_write and allow_read restricted strictly inside workspaceRoot
	for _, p := range untrusted.Filesystem.AllowWrite {
		if IsPathWithinWorkspace(p, workspaceRoot) {
			out.Filesystem.AllowWrite = appendUnique(out.Filesystem.AllowWrite, p)
		} else {
			issues = append(issues, ValidationIssue{
				Field:    "filesystem.allow_write",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Workspace config allow_write path %q outside workspace boundary stripped (AIR-02).", p),
			})
		}
	}
	for _, p := range untrusted.Filesystem.AllowRead {
		if IsPathWithinWorkspace(p, workspaceRoot) {
			out.Filesystem.AllowRead = appendUnique(out.Filesystem.AllowRead, p)
		} else {
			issues = append(issues, ValidationIssue{
				Field:    "filesystem.allow_read",
				Severity: "WARNING",
				Message:  fmt.Sprintf("Workspace config allow_read path %q outside workspace boundary stripped (AIR-02).", p),
			})
		}
	}
	if len(untrusted.Filesystem.DenyRead) > 0 {
		out.Filesystem.DenyRead = appendUnique(out.Filesystem.DenyRead, untrusted.Filesystem.DenyRead...)
	}
	if len(untrusted.Filesystem.DenyWrite) > 0 {
		out.Filesystem.DenyWrite = appendUnique(out.Filesystem.DenyWrite, untrusted.Filesystem.DenyWrite...)
	}

	// 6. Vetting: workspace config MUST NEVER populate ignored_rules or disable vetting
	if untrusted.Vetting.Enable {
		out.Vetting.Enable = true
	}
	if untrusted.Vetting.Strict {
		out.Vetting.Strict = true
	}
	if len(untrusted.Vetting.IgnoredRules) > 0 {
		issues = append(issues, ValidationIssue{
			Field:    "vetting.ignored_rules",
			Severity: "WARNING",
			Message:  fmt.Sprintf("Workspace config attempted to ignore vetting rules (%v); stripped by monotonic attenuation (AIR-02).", untrusted.Vetting.IgnoredRules),
		})
	}

	// 7. Interactive: may only disable prompts, never force-enable them when base disables them
	if !untrusted.Interactive.PromptOnUnknownDomain {
		out.Interactive.PromptOnUnknownDomain = false
	}

	return out, issues
}

func cloneConfig(src *Config) *Config {
	if src == nil {
		return DefaultConfig()
	}
	c := *src
	c.Network.AllowDomains = append([]string(nil), src.Network.AllowDomains...)
	c.Network.AllowedUnixSockets = append([]string(nil), src.Network.AllowedUnixSockets...)
	c.Network.AllowedLoopbackPorts = append([]int(nil), src.Network.AllowedLoopbackPorts...)
	c.Env.Allow = append([]string(nil), src.Env.Allow...)
	c.Env.Deny = append([]string(nil), src.Env.Deny...)
	c.Filesystem.AllowRead = append([]string(nil), src.Filesystem.AllowRead...)
	c.Filesystem.AllowWrite = append([]string(nil), src.Filesystem.AllowWrite...)
	c.Filesystem.DenyRead = append([]string(nil), src.Filesystem.DenyRead...)
	c.Filesystem.DenyWrite = append([]string(nil), src.Filesystem.DenyWrite...)
	c.Vetting.IgnoredRules = append([]string(nil), src.Vetting.IgnoredRules...)
	return &c
}

func appendUnique(dst []string, vals ...string) []string {
	seen := make(map[string]bool, len(dst)+len(vals))
	for _, v := range dst {
		seen[v] = true
	}
	for _, v := range vals {
		trimmed := strings.TrimSpace(v)
		if trimmed != "" && !seen[trimmed] {
			seen[trimmed] = true
			dst = append(dst, trimmed)
		}
	}
	return dst
}
