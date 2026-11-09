// Package seatbelt synthesizes hardened Apple Seatbelt Profile Language (SBPL)
// profiles for process confinement on macOS.
package seatbelt

import (
	"bytes"
	_ "embed"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

//go:embed dev-agent.sb
var devAgentProfileTemplate string

// Params contains parameters interpolated into the Seatbelt Scheme profile.
type Params struct {
	Profile              string
	UserHome             string
	UserHomeData         string
	WorkspaceRoot        string
	WorkspaceRootEscaped string
	ScratchDir           string
	Airgap               bool
	ProxyPort            int
	AllowDirectNet       bool
	ExtraAllowRead       []string
	ExtraAllowWrite      []string
	ExtraDenyRead        []string
	ExtraDenyWrite       []string
	AntiLoopback         bool
	AllowedUnixSockets   []string
	AllowedLoopbackPorts []int
}

// Generator defines the interface for generating platform confinement profiles.
type Generator interface {
	Generate(p Params) (string, error)
}

// ProfileGenerator generates hardened macOS Seatbelt Scheme policies.
type ProfileGenerator struct{}

// NewGenerator creates a new Seatbelt profile generator.
func NewGenerator() *ProfileGenerator {
	return &ProfileGenerator{}
}

const profileTemplate = `;; Airlock Hardened Confinement Policy
(version 1)
(deny default)

(define workspace-root (if (param "WORKSPACE_ROOT") (param "WORKSPACE_ROOT") "{{.WorkspaceRoot}}"))
(define scratch-dir (if (param "SCRATCH_DIR") (param "SCRATCH_DIR") "{{.ScratchDir}}"))

;; 1. Core Process Lifecycle & System Discovery
(allow process-fork)
(allow process-exec)
(allow sysctl-read)

;; 2. Terminal and Pseudo-Device I/O & File Locking
(allow file-read* file-write*
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/dtracehelper")
  (regex #"^/dev/tty.*")
  (regex #"^/dev/ptmx.*"))

;; Block controlling terminal ioctl injection such as TIOCSTI (AIR-06 / V-05)
(deny file-ioctl (literal "/dev/tty"))

(allow file-lock)
(allow ipc-posix-shm*)

;; 3. Mach IPC Hardening (V-10: Neutralize Keychain, LaunchServices, Clipboard, TCC)
(deny mach-lookup
  (global-name "com.apple.securityd")
  (global-name "com.apple.CoreAuthentication.daemon")
  (global-name "com.apple.accountsd")
  (global-name "com.apple.keychainsharingreferent")
  (global-name "com.apple.coreservices.launchservicesd")
  (global-name "com.apple.pasteboard.pboard")
  (global-name "com.apple.tccd"))

(allow mach-lookup
  (global-name "com.apple.system.logger")
  (global-name "com.apple.system.notification_center")
  (global-name "com.apple.trustd.agent")
  (global-name "com.apple.trustd"))

;; 4. Filesystem Read Policy: Allow system reads; denials follow all allows below
(allow file-read*)
{{range .ExtraAllowRead}}
(allow file-read* (subpath "{{.}}"))
{{end}}

;; 5. Filesystem Write Policy: Strictly confined to Workspace, Scratch, and System Temp (V-03)
(deny file-write*)

(allow file-write*
  (subpath workspace-root)
  (subpath scratch-dir)
  (subpath "/tmp")
  (subpath "/private/tmp"))
{{range .ExtraAllowWrite}}
(allow file-write* (subpath "{{.}}"))
{{end}}

;; 5b. High-Precedence Credential, Secret & Metadata Denials (AIR-01 / AIR-05)
;; Placed strictly AFTER all file-read* and file-write* allows so denials always win.

;; Block host secrets and package/orchestrator credentials (V-01 / AIR-05)
(deny file-read* file-write* file-link
  (subpath "{{.UserHome}}/.ssh")
  (subpath "{{.UserHome}}/.aws")
  (subpath "{{.UserHome}}/.gnupg")
  (subpath "{{.UserHome}}/.kube")
  (subpath "{{.UserHome}}/.docker")
  (subpath "{{.UserHome}}/.fabrial")
  (subpath "{{.UserHome}}/.config/gcloud")
  (literal "{{.UserHome}}/.npmrc")
  (subpath "{{.UserHome}}/.npmrc")
  (literal "{{.UserHome}}/.pypirc")
  (subpath "{{.UserHome}}/.pypirc")
  (literal "{{.UserHome}}/.netrc")
  (subpath "{{.UserHome}}/.netrc"))

{{if .UserHomeData}}
(deny file-read* file-write* file-link
  (subpath "{{.UserHomeData}}/.ssh")
  (subpath "{{.UserHomeData}}/.aws")
  (subpath "{{.UserHomeData}}/.gnupg")
  (subpath "{{.UserHomeData}}/.kube")
  (subpath "{{.UserHomeData}}/.docker")
  (subpath "{{.UserHomeData}}/.fabrial")
  (subpath "{{.UserHomeData}}/.config/gcloud")
  (literal "{{.UserHomeData}}/.npmrc")
  (subpath "{{.UserHomeData}}/.npmrc")
  (literal "{{.UserHomeData}}/.pypirc")
  (subpath "{{.UserHomeData}}/.pypirc")
  (literal "{{.UserHomeData}}/.netrc")
  (subpath "{{.UserHomeData}}/.netrc"))
{{end}}

;; Fallback defense-in-depth regex for non-standard user profiles
(deny file-read* file-write* file-link
  (regex #"^(/System/Volumes/Data)?/(Users|home)/[^/]+/\.(ssh|aws|gnupg|kube|docker|fabrial|npmrc|pypirc|netrc|config/gcloud)"))

;; Block Docker daemon socket (V-06: Localhost Pivoting)
(deny file-read* file-write* file-link
  (literal "/var/run/docker.sock")
  (literal "/private/var/run/docker.sock"))

;; Block access to launchd listeners in /tmp (V-10: ssh-agent socket protection)
(deny file-read* file-write* file-link
  (regex #"^(/private)?/tmp/com\.apple\.launchd\..*"))

;; Mask project secret files across workspace and all subdirectories (V-04 / AIR-05: strict .pem/.key masking)
(deny file-read* file-write* file-link
  (subpath (string-append workspace-root "/.env"))
  (subpath "{{.WorkspaceRoot}}/.env")
  (regex (string-append "^" "{{.WorkspaceRootEscaped}}" #"/(.*/)?\.env(\..+)?$"))
  (regex (string-append "^" "{{.WorkspaceRootEscaped}}" #"/.*\.pem$"))
  (regex (string-append "^" "{{.WorkspaceRootEscaped}}" #"/.*\.key$"))
  (regex (string-append "^" "{{.WorkspaceRootEscaped}}" #"/(.*/)?(id_rsa|id_ed25519|id_ecdsa|id_dsa).*$"))
  (regex (string-append "^" "{{.WorkspaceRootEscaped}}" #"/(.*/)?(secrets|service-account)\.json$")))
{{range .ExtraDenyRead}}
(deny file-read* file-link (subpath "{{.}}"))
{{end}}

;; Prevent Workspace poisoning: protect .git directory from modification or hardlinking (V-03 / AIR-05)
(deny file-write* file-link
  (subpath (string-append workspace-root "/.git"))
  (subpath "{{.WorkspaceRoot}}/.git"))
{{range .ExtraDenyWrite}}
(deny file-write* file-link (subpath "{{.}}"))
{{end}}

;; 6. Network Egress Policy (V-02 & V-08)
{{if .Airgap}}
(deny network*)
{{else if gt .ProxyPort 0}}
;; Kernel-Enforced Egress Proxy: Deny external; permit ONLY to local proxy port
(deny network*)
(allow network-outbound (to tcp "localhost:{{.ProxyPort}}"))
(allow network-inbound (local tcp "localhost:{{.ProxyPort}}"))
{{else if .AllowDirectNet}}
;; Direct external networking permitted for development
(allow network-outbound (to tcp "*:443") (to tcp "*:80"))
(allow network-outbound (to udp "*:53"))
{{else}}
(deny network*)
{{end}}

{{if .AntiLoopback}}
;; Anti-Loopback Confinement (CVE-2026-25253: Mitigate OpenClaw loopback control-plane pivoting)
;; Deny network-outbound to localhost / 127.0.0.1 / [::1] control planes
(deny network-outbound
  (to ip "localhost:*")
  (to tcp "localhost:8080")
  (to tcp "localhost:9090")
  (to tcp "localhost:2375")
  (to tcp "localhost:11434"))
{{if gt .ProxyPort 0}}
;; Re-allow supervisor egress proxy port
(allow network-outbound (to tcp "localhost:{{.ProxyPort}}"))
(allow network-inbound (local tcp "localhost:{{.ProxyPort}}"))
{{end}}
{{range .AllowedLoopbackPorts}}
(allow network-outbound (to tcp "localhost:{{.}}"))
{{end}}
{{end}}

{{if .AllowedUnixSockets}}
(allow network-outbound (remote unix-socket))
{{range .AllowedUnixSockets}}
;; Whitelisted Unix Domain Sockets (CVE-2026-25253: explicit IPC whitelist)
(allow network-outbound (literal "{{.}}") (subpath "{{.}}"))
(allow file-read* file-write* (literal "{{.}}") (subpath "{{.}}"))
{{end}}
{{end}}
`

// EscapeSBPLString validates and escapes a string literal before emitting it inside
// a double-quoted Apple Seatbelt SBPL string. It rejects control characters (NUL, CR, LF)
// to neutralize S-expression injection and escapes backslashes and double quotes (AIR-01).
func EscapeSBPLString(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\r\n") {
		return "", fmt.Errorf("seatbelt: illegal control character in path or literal")
	}
	escaped := strings.ReplaceAll(s, `\`, `\\`)
	escaped = strings.ReplaceAll(escaped, `"`, `\"`)
	return escaped, nil
}

// ValidateParamValue verifies a raw value passed via sandbox-exec -D KEY=VALUE (AIR-01).
func ValidateParamValue(s string) (string, error) {
	if strings.ContainsAny(s, "\x00\r\n") {
		return "", fmt.Errorf("seatbelt: illegal control character in sandbox-exec parameter")
	}
	return s, nil
}

// SandboxExecArgs constructs parameterized sandbox-exec CLI arguments (-D WORKSPACE_ROOT=... -D SCRATCH_DIR=... -p <profile>).
func SandboxExecArgs(workspaceRoot, scratchDir, profile string, cmdArgs []string) ([]string, error) {
	if resolved, err := filepath.EvalSymlinks(workspaceRoot); err == nil && resolved != "" {
		workspaceRoot = resolved
	}
	if resolved, err := filepath.EvalSymlinks(scratchDir); err == nil && resolved != "" {
		scratchDir = resolved
	}
	if _, err := ValidateParamValue(workspaceRoot); err != nil {
		return nil, err
	}
	if _, err := ValidateParamValue(scratchDir); err != nil {
		return nil, err
	}
	args := make([]string, 0, 6+len(cmdArgs))
	args = append(args,
		"-D", "WORKSPACE_ROOT="+workspaceRoot,
		"-D", "SCRATCH_DIR="+scratchDir,
		"-p", profile,
	)
	args = append(args, cmdArgs...)
	return args, nil
}

// Generate renders the hardened Seatbelt Scheme profile string.
func (g *ProfileGenerator) Generate(p Params) (string, error) {
	if p.UserHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("seatbelt: failed to get user home directory: %w", err)
		}
		p.UserHome = home
	}

	// Reject control characters on raw inputs before symlink evaluation
	for _, rawInput := range []string{p.UserHome, p.WorkspaceRoot, p.ScratchDir} {
		if _, err := ValidateParamValue(rawInput); err != nil {
			return "", err
		}
	}

	// Canonicalize paths to resolve symlinks
	if resolved, err := filepath.EvalSymlinks(p.UserHome); err == nil {
		p.UserHome = resolved
	}
	if resolved, err := filepath.EvalSymlinks(p.WorkspaceRoot); err == nil {
		p.WorkspaceRoot = resolved
	}
	if resolved, err := filepath.EvalSymlinks(p.ScratchDir); err == nil {
		p.ScratchDir = resolved
	}

	rawUserHome := p.UserHome
	rawWorkspaceRoot := p.WorkspaceRoot

	// Determine physical data volume path on macOS (/System/Volumes/Data/Users/...)
	rawUserHomeData := ""
	if strings.HasPrefix(rawUserHome, "/Users/") {
		rawUserHomeData = path.Join("/System/Volumes/Data", filepath.ToSlash(rawUserHome))
	}

	expandAndEscapePaths := func(paths []string) ([]string, error) {
		var out []string
		for _, raw := range paths {
			if _, err := ValidateParamValue(raw); err != nil {
				return nil, err
			}
			cleaned := strings.TrimSpace(raw)
			if cleaned == "" {
				continue
			}
			if strings.HasPrefix(cleaned, "~/") {
				cleaned = filepath.Join(rawUserHome, cleaned[2:])
			}
			escaped, err := EscapeSBPLString(cleaned)
			if err != nil {
				return nil, err
			}
			out = append(out, escaped)
		}
		return out, nil
	}

	var err error
	if p.ExtraAllowRead, err = expandAndEscapePaths(p.ExtraAllowRead); err != nil {
		return "", err
	}
	if p.ExtraAllowWrite, err = expandAndEscapePaths(p.ExtraAllowWrite); err != nil {
		return "", err
	}
	if p.ExtraDenyRead, err = expandAndEscapePaths(p.ExtraDenyRead); err != nil {
		return "", err
	}
	if p.ExtraDenyWrite, err = expandAndEscapePaths(p.ExtraDenyWrite); err != nil {
		return "", err
	}
	if p.AllowedUnixSockets, err = expandAndEscapePaths(p.AllowedUnixSockets); err != nil {
		return "", err
	}

	if p.ProxyPort < 0 || p.ProxyPort > 65535 {
		return "", fmt.Errorf("seatbelt: invalid proxy port %d", p.ProxyPort)
	}
	for _, port := range p.AllowedLoopbackPorts {
		if port <= 0 || port > 65535 {
			return "", fmt.Errorf("seatbelt: invalid allowed loopback port %d", port)
		}
	}

	// Anti-loopback is default enabled for agent profiles and anti-loopback profile
	if strings.EqualFold(p.Profile, "anti-loopback") ||
		strings.EqualFold(p.Profile, "anti_loopback") ||
		strings.EqualFold(p.Profile, "dev-agent") ||
		strings.EqualFold(p.Profile, "dev_agent") ||
		strings.EqualFold(p.Profile, "agent") ||
		strings.EqualFold(p.Profile, "strict-agent") {
		p.AntiLoopback = true
	}

	// Escape all dynamic path literals & regex prefixes for SBPL (AIR-01)
	if p.UserHome, err = EscapeSBPLString(rawUserHome); err != nil {
		return "", err
	}
	if rawUserHomeData != "" {
		if p.UserHomeData, err = EscapeSBPLString(rawUserHomeData); err != nil {
			return "", err
		}
	}
	if p.WorkspaceRoot, err = EscapeSBPLString(rawWorkspaceRoot); err != nil {
		return "", err
	}
	if p.ScratchDir, err = EscapeSBPLString(p.ScratchDir); err != nil {
		return "", err
	}
	if p.WorkspaceRootEscaped, err = EscapeSBPLString(regexp.QuoteMeta(rawWorkspaceRoot)); err != nil {
		return "", err
	}

	selectedTemplate := profileTemplate
	if strings.EqualFold(p.Profile, "dev-agent") || strings.EqualFold(p.Profile, "dev_agent") {
		selectedTemplate = devAgentProfileTemplate
	}

	tmpl, err := template.New("seatbelt").Parse(selectedTemplate)
	if err != nil {
		return "", fmt.Errorf("seatbelt: failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("seatbelt: failed to execute template: %w", err)
	}

	return buf.String(), nil
}

// GenerateDevAgent renders the dedicated dev-agent Seatbelt profile.
func (g *ProfileGenerator) GenerateDevAgent(p Params) (string, error) {
	p.Profile = "dev-agent"
	return g.Generate(p)
}

// GenerateAntiLoopback renders the dedicated anti-loopback Seatbelt profile.
func (g *ProfileGenerator) GenerateAntiLoopback(p Params) (string, error) {
	p.Profile = "anti-loopback"
	p.AntiLoopback = true
	return g.Generate(p)
}
