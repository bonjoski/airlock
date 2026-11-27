package profile

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

// UntrustedAgentProfileName is the canonical profile identifier for strictly confined
// third-party autonomous agent frameworks (RFC-2026-11-27-70).
const UntrustedAgentProfileName = "untrusted-agent"

// UntrustedAgentDefaultPATH restricts child binaries exclusively to immutable system
// directories, stripping workspace-relative (., ./bin) and user-writable (~/.local/bin) paths.
var UntrustedAgentDefaultPATH = []string{"/usr/bin", "/bin", "/opt/homebrew/bin"}

// UntrustedAgentScrubEnvPrefixes enumerates ambient credential and runtime-injection
// environment variable prefixes unconditionally stripped before exec inside the jail.
var UntrustedAgentScrubEnvPrefixes = []string{
	"AWS_",
	"ANTHROPIC_",
	"OPENAI_",
	"GEMINI_",
	"GOOGLE_API_",
	"GITHUB_TOKEN",
	"GH_TOKEN",
	"AZURE_",
	"GCP_",
	"STRIPE_",
	"SLACK_",
	"SSH_AUTH_SOCK",
	"LD_PRELOAD",
	"DYLD_INSERT_LIBRARIES",
	"PYTHONPATH",
	"NODE_OPTIONS",
}

// untrustedAgentExtraScrubPrefixes covers additional dynamic-linker and git injection vars.
var untrustedAgentExtraScrubPrefixes = []string{
	"DYLD_FORCE_FLAT_NAMESPACE",
	"DYLD_LIBRARY_PATH",
	"LD_LIBRARY_PATH",
	"GIT_CONFIG_",
}

// UntrustedAgentDefaultDenyPaths enumerates host credential directories, SSH persistence files,
// shell rc files, LaunchAgents, cron directories, and host sockets strictly denied read and write.
var UntrustedAgentDefaultDenyPaths = []string{
	"~/.ssh",
	"~/.ssh/authorized_keys",
	"~/.aws",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gh",
	"~/.config/gcloud",
	"~/.azure",
	"~/.bashrc",
	"~/.zshrc",
	"~/.profile",
	"~/Library/LaunchAgents",
	"/etc/crontab",
	"/etc/cron.d",
	"/etc/cron.daily",
	"/etc/cron.hourly",
	"/etc/cron.weekly",
	"/etc/cron.monthly",
	"/var/run/docker.sock",
	".env",
	".env.*",
}

// UntrustedAgentConfig configures confinement parameters for the untrusted-agent profile.
type UntrustedAgentConfig struct {
	WorkDir            string
	AllowEgressHosts   []string // Declared API hostnames only (e.g. ["api.anthropic.com"])
	KeylessProxyAddr   string   // Optional strict loopback 127.0.0.1:<port> or [::1]:<port>
	AllowedPlaceholder []string // Optional env var names receiving CSPRNG placeholder tokens
}

var (
	shellMetaChars      = ";|&$()`<>\\'\"{}[]!~?#*\r\n\t \x00"
	dnsLabelRe          = regexp.MustCompile(`^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$`)
	placeholderEnvKeyRe = regexp.MustCompile(`^[A-Z][A-Z0-9_]{0,127}$`)
	cgnatPrefix         = netip.MustParsePrefix("100.64.0.0/10")
	linkLocalV4Prefix   = netip.MustParsePrefix("169.254.0.0/16")
)

// ValidateEgressAllowlist enforces strict fail-closed validation on declared egress hosts.
// It rejects empty/whitespace strings, wildcards (*), shell metacharacters, URL schemes/paths,
// loopback/RFC1918/CGNAT/link-local/IMDS (169.254.169.254) IP literals, and non-FQDN hostnames.
func ValidateEgressAllowlist(hosts []string) error {
	for _, raw := range hosts {
		if raw == "" || strings.TrimSpace(raw) == "" {
			return fmt.Errorf("untrusted-agent: empty or whitespace egress host is forbidden")
		}
		if strings.ContainsAny(raw, shellMetaChars) {
			return fmt.Errorf("untrusted-agent: egress host %q contains forbidden metacharacters, wildcard, or whitespace", raw)
		}
		if strings.Contains(raw, "://") || strings.Contains(raw, "/") || strings.Contains(raw, "@") {
			return fmt.Errorf("untrusted-agent: egress host %q must be a bare hostname (no scheme, path, or userinfo)", raw)
		}

		host := strings.ToLower(raw)
		// Strip optional :port (strictly 1..65535)
		if strings.HasPrefix(host, "[") {
			// Bracketed IPv6 literal — inspect raw IP below
			endBracket := strings.Index(host, "]")
			if endBracket == -1 {
				return fmt.Errorf("untrusted-agent: malformed IPv6 literal %q", raw)
			}
			inner := host[1:endBracket]
			rest := host[endBracket+1:]
			if rest != "" {
				if !strings.HasPrefix(rest, ":") {
					return fmt.Errorf("untrusted-agent: malformed host:port %q", raw)
				}
				if err := validatePortString(rest[1:]); err != nil {
					return fmt.Errorf("untrusted-agent: %w in %q", err, raw)
				}
			}
			if err := rejectForbiddenIPLiteral(inner, raw); err != nil {
				return err
			}
			continue
		}

		// Handle unbracketed IPv6 literals directly
		if strings.Count(host, ":") > 1 {
			if err := rejectForbiddenIPLiteral(host, raw); err != nil {
				return err
			}
			continue
		}

		if idx := strings.LastIndex(host, ":"); idx != -1 {
			if err := validatePortString(host[idx+1:]); err != nil {
				return fmt.Errorf("untrusted-agent: %w in %q", err, raw)
			}
			host = host[:idx]
		}

		host = strings.TrimSuffix(host, ".")
		if host == "" {
			return fmt.Errorf("untrusted-agent: empty hostname in %q", raw)
		}

		// Reject direct IPv4 literals in private/RFC1918/loopback/link-local/IMDS/CGNAT ranges
		if addr, err := netip.ParseAddr(host); err == nil {
			if err := checkAllowedIPAddr(addr, raw); err != nil {
				return err
			}
			continue
		}

		// Reject alternate integer/hex/octal IPv4 obfuscation (e.g. 0x7f000001, 2130706433, 0177.0.0.1)
		if isObfuscatedIPLiteral(host) {
			return fmt.Errorf("untrusted-agent: numeric or obfuscated IP literal %q is forbidden in egress allowlist", raw)
		}

		if host == "localhost" || strings.HasSuffix(host, ".localhost") || strings.HasSuffix(host, ".local") || strings.HasSuffix(host, ".internal") {
			return fmt.Errorf("untrusted-agent: local/internal hostname %q is forbidden in egress allowlist", raw)
		}

		labels := strings.Split(host, ".")
		if len(labels) < 2 {
			return fmt.Errorf("untrusted-agent: egress host %q must be a fully-qualified domain name", raw)
		}
		for _, lbl := range labels {
			if !dnsLabelRe.MatchString(lbl) {
				return fmt.Errorf("untrusted-agent: invalid DNS label %q in egress host %q", lbl, raw)
			}
		}
		// Reject all-numeric TLD (catches malformed dotted-quads)
		lastLabel := labels[len(labels)-1]
		if _, err := strconv.Atoi(lastLabel); err == nil {
			return fmt.Errorf("untrusted-agent: numeric TLD in %q is forbidden", raw)
		}
	}
	return nil
}

func validatePortString(p string) error {
	port, err := strconv.Atoi(p)
	if err != nil || port < 1 || port > 65535 {
		return fmt.Errorf("invalid port %q", p)
	}
	return nil
}

func rejectForbiddenIPLiteral(ipStr, raw string) error {
	addr, err := netip.ParseAddr(ipStr)
	if err != nil {
		return fmt.Errorf("untrusted-agent: invalid IP literal %q", raw)
	}
	return checkAllowedIPAddr(addr, raw)
}

func checkAllowedIPAddr(addr netip.Addr, raw string) error {
	unmapped := addr.Unmap()
	if unmapped.IsLoopback() ||
		unmapped.IsPrivate() ||
		unmapped.IsLinkLocalUnicast() ||
		unmapped.IsLinkLocalMulticast() ||
		unmapped.IsUnspecified() ||
		unmapped.IsMulticast() ||
		cgnatPrefix.Contains(unmapped) ||
		linkLocalV4Prefix.Contains(unmapped) {
		return fmt.Errorf("untrusted-agent: private, loopback, link-local, or cloud IMDS IP %q is forbidden in egress allowlist", raw)
	}
	return nil
}

func isObfuscatedIPLiteral(host string) bool {
	// Pure integer (e.g. 2852039166 for 169.254.169.254) or hex (0xa9fea9fe) or octal (025177524776)
	if _, err := strconv.ParseUint(host, 0, 64); err == nil {
		return true
	}
	parts := strings.Split(host, ".")
	if len(parts) >= 2 && len(parts) <= 4 {
		allNumeric := true
		for _, p := range parts {
			if _, err := strconv.ParseUint(p, 0, 32); err != nil {
				allNumeric = false
				break
			}
		}
		if allNumeric {
			return true
		}
	}
	return false
}

// ValidateKeylessProxyAddr parses and validates addr using netip.ParseAddrPort,
// strictly permitting ONLY canonical loopback IP literals (127.0.0.1:<port> or [::1]:<port>).
// Hostnames, non-loopback IPs, IPv4-mapped IPv6 addresses, port 0, and metacharacters are rejected fail-closed.
func ValidateKeylessProxyAddr(addr string) (netip.AddrPort, error) {
	trimmed := strings.TrimSpace(addr)
	if trimmed == "" {
		return netip.AddrPort{}, fmt.Errorf("untrusted-agent: keyless proxy address must not be empty")
	}
	if strings.ContainsAny(trimmed, ";|&$()`<>\\'\"{}!~?#*\r\n\t \x00/@") {
		return netip.AddrPort{}, fmt.Errorf("untrusted-agent: keyless proxy address %q contains illegal characters", addr)
	}
	ap, err := netip.ParseAddrPort(trimmed)
	if err != nil {
		return netip.AddrPort{}, fmt.Errorf("untrusted-agent: keyless proxy address %q must be a strict loopback ip:port (127.0.0.1:<port> or [::1]:<port>): %w", addr, err)
	}
	if ap.Port() == 0 {
		return netip.AddrPort{}, fmt.Errorf("untrusted-agent: keyless proxy port must be non-zero in %q", addr)
	}
	ip := ap.Addr()
	if ip.Is4In6() {
		return netip.AddrPort{}, fmt.Errorf("untrusted-agent: IPv4-mapped IPv6 proxy address %q is forbidden; use 127.0.0.1:<port> or [::1]:<port>", addr)
	}
	v4Loop := netip.MustParseAddr("127.0.0.1")
	v6Loop := netip.MustParseAddr("::1")
	if ip != v4Loop && ip != v6Loop {
		return netip.AddrPort{}, fmt.Errorf("untrusted-agent: keyless proxy address %q must bind strictly to loopback 127.0.0.1 or ::1", addr)
	}
	return ap, nil
}

func isScrubbedUntrustedEnvKey(key string) bool {
	upper := strings.ToUpper(strings.TrimSpace(key))
	if upper == "" {
		return true
	}
	for _, prefix := range UntrustedAgentScrubEnvPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	for _, prefix := range untrustedAgentExtraScrubPrefixes {
		if strings.HasPrefix(upper, prefix) {
			return true
		}
	}
	return false
}

// BuildUntrustedAgentEnv scrubs all ambient cloud/LLM/SSH/linker credentials from baseEnv,
// forces PATH to the immutable UntrustedAgentDefaultPATH allowlist, and optionally injects
// loopback proxy settings and CSPRNG session-scoped placeholder tokens when KeylessProxyAddr is set.
func BuildUntrustedAgentEnv(baseEnv []string, cfg UntrustedAgentConfig) ([]string, error) {
	if len(cfg.AllowEgressHosts) > 0 {
		if err := ValidateEgressAllowlist(cfg.AllowEgressHosts); err != nil {
			return nil, err
		}
	}

	var proxyAP netip.AddrPort
	if cfg.KeylessProxyAddr != "" {
		ap, err := ValidateKeylessProxyAddr(cfg.KeylessProxyAddr)
		if err != nil {
			return nil, err
		}
		proxyAP = ap
	} else if len(cfg.AllowedPlaceholder) > 0 {
		return nil, fmt.Errorf("untrusted-agent: AllowedPlaceholder requires a validated loopback KeylessProxyAddr")
	}

	type kv struct {
		key string
		val string
	}
	order := make([]string, 0, len(baseEnv)+8)
	entries := make(map[string]kv, len(baseEnv)+8)

	setEnv := func(k, v string) {
		if _, exists := entries[k]; !exists {
			order = append(order, k)
		}
		entries[k] = kv{key: k, val: v}
	}

	for _, raw := range baseEnv {
		idx := strings.Index(raw, "=")
		if idx <= 0 {
			continue
		}
		k := raw[:idx]
		v := raw[idx+1:]
		upper := strings.ToUpper(k)

		// Always replace PATH below with immutable system directories
		if upper == "PATH" {
			continue
		}
		// Unconditionally strip all ambient secrets and runtime injection vars
		if isScrubbedUntrustedEnvKey(k) {
			continue
		}
		// Strip proxy env vars when WAN=DENY so ambient host proxies cannot redirect traffic
		if cfg.KeylessProxyAddr == "" && len(cfg.AllowEgressHosts) == 0 {
			if upper == "HTTP_PROXY" || upper == "HTTPS_PROXY" || upper == "ALL_PROXY" || upper == "PIP_PROXY" || upper == "NPM_CONFIG_PROXY" {
				continue
			}
		}

		setEnv(k, v)
	}

	// Enforce strict immutable system PATH (strips ., ./bin, ~/.local/bin, writable dirs)
	immutablePath := strings.Join(UntrustedAgentDefaultPATH, string(os.PathListSeparator))
	setEnv("PATH", immutablePath)

	// Wire loopback keyless proxy and CSPRNG session-scoped placeholder tokens
	if cfg.KeylessProxyAddr != "" {
		proxyURL := "http://" + proxyAP.String()
		setEnv("HTTP_PROXY", proxyURL)
		setEnv("HTTPS_PROXY", proxyURL)
		setEnv("http_proxy", proxyURL)
		setEnv("https_proxy", proxyURL)

		for _, keyName := range cfg.AllowedPlaceholder {
			cleanKey := strings.TrimSpace(keyName)
			if !placeholderEnvKeyRe.MatchString(cleanKey) || cleanKey == "PATH" || config.IsForbiddenEnv(cleanKey) || cleanKey == "PYTHONPATH" || cleanKey == "NODE_OPTIONS" {
				return nil, fmt.Errorf("untrusted-agent: invalid placeholder env key %q", keyName)
			}
			tok, err := generatePlaceholderToken()
			if err != nil {
				return nil, err
			}
			setEnv(cleanKey, tok)
		}
	}

	result := make([]string, 0, len(order))
	for _, upper := range order {
		pair := entries[upper]
		result = append(result, pair.key+"="+pair.val)
	}
	return result, nil
}

func generatePlaceholderToken() (string, error) {
	var raw [16]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return "", fmt.Errorf("untrusted-agent: failed to generate CSPRNG placeholder token: %w", err)
	}
	return "locksmith_placeholder_" + hex.EncodeToString(raw[:]), nil
}

// GenerateUntrustedAgentSeatbelt synthesizes a hardened macOS Seatbelt SBPL policy for
// third-party untrusted agent frameworks. It enforces WAN=DENY by default when no egress
// hosts or keyless proxy are configured, blocks loopback probing except the declared proxy
// port, and explicitly denies read/write/link access to ~/.ssh, ~/.ssh/authorized_keys,
// ~/.bashrc, ~/.zshrc, ~/.profile, ~/Library/LaunchAgents, and /etc/cron*.
func GenerateUntrustedAgentSeatbelt(p seatbelt.Params, cfg UntrustedAgentConfig) (string, error) {
	if len(cfg.AllowEgressHosts) > 0 {
		if err := ValidateEgressAllowlist(cfg.AllowEgressHosts); err != nil {
			return "", err
		}
	}

	var proxyPort int
	if cfg.KeylessProxyAddr != "" {
		ap, err := ValidateKeylessProxyAddr(cfg.KeylessProxyAddr)
		if err != nil {
			return "", err
		}
		proxyPort = int(ap.Port())
	}

	if p.WorkspaceRoot == "" && cfg.WorkDir != "" {
		p.WorkspaceRoot = cfg.WorkDir
	}
	if p.UserHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("untrusted-agent: failed to resolve user home: %w", err)
		}
		p.UserHome = home
	}

	p.Profile = UntrustedAgentProfileName
	p.AntiLoopback = true
	p.AllowDirectNet = false // Untrusted agents NEVER receive direct WAN socket access

	// Default WAN=DENY when neither declared egress allowlist nor keyless proxy is active
	if len(cfg.AllowEgressHosts) == 0 && cfg.KeylessProxyAddr == "" {
		p.Airgap = true
		p.ProxyPort = 0
		p.AllowedLoopbackPorts = nil
	} else if proxyPort > 0 {
		p.Airgap = false
		if p.ProxyPort == 0 {
			p.ProxyPort = proxyPort
		} else if p.ProxyPort != proxyPort {
			p.AllowedLoopbackPorts = append(p.AllowedLoopbackPorts, proxyPort)
		}
	} else {
		// AllowEgressHosts configured: if caller provided an Airlock proxy port, allow only that
		// loopback proxy; if ProxyPort == 0, Seatbelt stays fail-closed (deny network*).
		p.Airgap = (p.ProxyPort == 0)
	}

	// Ensure every host credential and persistence path is denied for BOTH read and write
	for _, deny := range UntrustedAgentDefaultDenyPaths {
		if deny == ".env" || deny == ".env.*" {
			continue // Already covered by workspace secret regex rules in base template
		}
		p.ExtraDenyRead = append(p.ExtraDenyRead, deny)
		p.ExtraDenyWrite = append(p.ExtraDenyWrite, deny)
	}

	gen := seatbelt.NewGenerator()
	baseSBPL, err := gen.Generate(p)
	if err != nil {
		return "", err
	}

	// Append high-precedence persistence & cron wildcard deny block strictly after all file allows
	resolvedHome := p.UserHome
	if eval, err := filepath.EvalSymlinks(resolvedHome); err == nil && eval != "" {
		resolvedHome = eval
	}
	escHome, err := seatbelt.EscapeSBPLString(resolvedHome)
	if err != nil {
		return "", err
	}

	var extra strings.Builder
	extra.WriteString("\n;; Untrusted-Agent Persistence & SSH Lock (RFC-2026-11-27-70)\n")
	extra.WriteString("(deny file-read* file-write* file-link\n")
	extra.WriteString(fmt.Sprintf("  (literal \"%s/.ssh/authorized_keys\")\n", escHome))
	extra.WriteString(fmt.Sprintf("  (literal \"%s/.bashrc\")\n", escHome))
	extra.WriteString(fmt.Sprintf("  (literal \"%s/.zshrc\")\n", escHome))
	extra.WriteString(fmt.Sprintf("  (literal \"%s/.profile\")\n", escHome))
	extra.WriteString(fmt.Sprintf("  (subpath \"%s/Library/LaunchAgents\")\n", escHome))
	if strings.HasPrefix(resolvedHome, "/Users/") {
		dataHome := path.Join("/System/Volumes/Data", filepath.ToSlash(resolvedHome))
		if escDataHome, err := seatbelt.EscapeSBPLString(dataHome); err == nil {
			extra.WriteString(fmt.Sprintf("  (literal \"%s/.ssh/authorized_keys\")\n", escDataHome))
			extra.WriteString(fmt.Sprintf("  (literal \"%s/.bashrc\")\n", escDataHome))
			extra.WriteString(fmt.Sprintf("  (literal \"%s/.zshrc\")\n", escDataHome))
			extra.WriteString(fmt.Sprintf("  (literal \"%s/.profile\")\n", escDataHome))
			extra.WriteString(fmt.Sprintf("  (subpath \"%s/Library/LaunchAgents\")\n", escDataHome))
		}
	}
	extra.WriteString("  (regex #\"^/etc/cron.*\")\n")
	extra.WriteString("  (regex #\"^/private/etc/cron.*\"))\n")

	return baseSBPL + extra.String(), nil
}

// BuildUntrustedAgentLandlock synthesizes a strict fail-closed Linux Landlock LSM ruleset
// for the untrusted-agent profile. Unlike dev-agent, it omits user-writable home toolchains
// (~/.local/bin, ~/.cargo/bin, etc.) and filters out any extra paths targeting credentials
// or persistence locations (~/.ssh, ~/.bashrc, ~/.zshrc, ~/.profile, LaunchAgents, /etc/cron*).
func BuildUntrustedAgentLandlock(cfg landlock.Config, ua UntrustedAgentConfig) *landlock.Ruleset {
	wsRoot := cfg.WorkspaceRoot
	if wsRoot == "" {
		wsRoot = ua.WorkDir
	}

	rs := &landlock.Ruleset{
		HandledAccessFS: landlock.AccessFSAll,
		DenyPaths:       append([]string(nil), UntrustedAgentDefaultDenyPaths...),
		WorkspaceRoot:   wsRoot,
		ScratchDir:      cfg.ScratchDir,
	}

	// Immutable system directories only (Read-Only)
	for _, sys := range []string{"/usr", "/lib", "/lib64", "/bin", "/sbin"} {
		rs.Rules = append(rs.Rules, landlock.PathRule{
			Path:   sys,
			Access: landlock.AccessFSRead,
		})
	}

	// Workspace root (Read-Write)
	if wsRoot != "" {
		rs.Rules = append(rs.Rules, landlock.PathRule{
			Path:   wsRoot,
			Access: landlock.AccessFSAll,
		})
	}

	// Per-session ephemeral scratch directory (Read-Write)
	if cfg.ScratchDir != "" {
		rs.Rules = append(rs.Rules, landlock.PathRule{
			Path:   cfg.ScratchDir,
			Access: landlock.AccessFSAll,
		})
	}

	// Filter extra allowlists strictly against forbidden credential and persistence paths
	for _, p := range cfg.ExtraAllowRead {
		cleaned := strings.TrimSpace(p)
		if cleaned == "" || isUntrustedForbiddenPath(cleaned) {
			continue
		}
		rs.Rules = append(rs.Rules, landlock.PathRule{
			Path:   cleaned,
			Access: landlock.AccessFSRead,
		})
	}
	for _, p := range cfg.ExtraAllowWrite {
		cleaned := strings.TrimSpace(p)
		if cleaned == "" || isUntrustedForbiddenPath(cleaned) {
			continue
		}
		rs.Rules = append(rs.Rules, landlock.PathRule{
			Path:   cleaned,
			Access: landlock.AccessFSAll,
		})
	}

	return rs
}

func isUntrustedForbiddenPath(p string) bool {
	if config.IsForbiddenPath(p) {
		return true
	}
	norm := strings.ToLower(strings.ReplaceAll(strings.TrimSpace(p), "\\", "/"))
	persistenceSubstrings := []string{
		"authorized_keys",
		".bashrc",
		".zshrc",
		".profile",
		"launchagents",
		"/etc/cron",
		"/private/etc/cron",
		".azure",
	}
	for _, sub := range persistenceSubstrings {
		if strings.Contains(norm, sub) {
			return true
		}
	}
	return norm == "/" || norm == "/etc" || norm == "~"
}

// AugmentBwrapArgsForUntrustedAgent appends Bubblewrap isolation flags for the
// untrusted-agent profile: drops all Linux capabilities, enforces network namespace
// detachment (WAN=DENY) when no egress/proxy is configured, masks host credentials,
// shell persistence files, LaunchAgents, and /etc/cron*, pins immutable PATH, and
// unsets ambient secret variables.
func AugmentBwrapArgsForUntrustedAgent(args []string, userHome string, unreadableMask string, cfg UntrustedAgentConfig) []string {
	args = append(args, "--cap-drop", "ALL")

	// Enforce default WAN=DENY via network namespace detachment when no egress/proxy configured
	if len(cfg.AllowEgressHosts) == 0 && cfg.KeylessProxyAddr == "" {
		hasUnshareNet := false
		for _, a := range args {
			if a == "--unshare-net" {
				hasUnshareNet = true
				break
			}
		}
		if !hasUnshareNet {
			args = append(args, "--unshare-net")
		}
	}

	if unreadableMask != "" {
		args = append(args,
			"--tmpfs", "/proc/sys",
			"--ro-bind-try", unreadableMask, "/proc/kcore",
			"--ro-bind-try", unreadableMask, "/etc/crontab",
			"--ro-bind-try", unreadableMask, "/etc/cron.d",
			"--ro-bind-try", unreadableMask, "/etc/cron.daily",
			"--ro-bind-try", unreadableMask, "/etc/cron.hourly",
			"--ro-bind-try", unreadableMask, "/etc/cron.weekly",
			"--ro-bind-try", unreadableMask, "/etc/cron.monthly",
			"--ro-bind-try", unreadableMask, "/var/run/docker.sock",
		)

		if userHome != "" {
			for _, deny := range UntrustedAgentDefaultDenyPaths {
				if strings.HasPrefix(deny, "~/") {
					target := path.Join(filepath.ToSlash(userHome), deny[2:])
					args = append(args, "--ro-bind-try", unreadableMask, target)
				}
			}
		}
	}

	// Enforce immutable PATH inside bubblewrap container
	args = append(args, "--setenv", "PATH", strings.Join(UntrustedAgentDefaultPATH, ":"))

	// Unset high-risk ambient credential & linker vars defensively
	for _, key := range []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"AWS_SESSION_TOKEN",
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GEMINI_API_KEY",
		"GOOGLE_API_KEY",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"SSH_AUTH_SOCK",
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
		"PYTHONPATH",
		"NODE_OPTIONS",
	} {
		args = append(args, "--unsetenv", key)
	}

	return args
}
