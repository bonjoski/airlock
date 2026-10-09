// Package seatbelt synthesizes hardened Apple Seatbelt Profile Language (SBPL)
// profiles for process confinement on macOS.
package seatbelt

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"text/template"
)

// Params contains parameters interpolated into the Seatbelt Scheme profile.
type Params struct {
	UserHome             string
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

;; 1. Core Process Lifecycle & System Discovery
(allow process-fork)
(allow process-exec)
(allow sysctl-read)

;; 2. Terminal and Pseudo-Device I/O
(allow file-read* file-write*
  (literal "/dev/null")
  (literal "/dev/zero")
  (literal "/dev/random")
  (literal "/dev/urandom")
  (literal "/dev/dtracehelper")
  (regex #"^/dev/tty.*")
  (regex #"^/dev/ptmx.*"))

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
  (global-name "com.apple.system.notification_center"))

;; 4. Filesystem Read Policy: Allow system reads, but strictly block host and workspace secrets
(allow file-read*)
{{range .ExtraAllowRead}}
(allow file-read* (subpath "{{.}}"))
{{end}}

;; Block host secrets (V-01: Explicit Evaluated Absolute Paths)
(deny file-read* file-write*
  (subpath "{{.UserHome}}/.ssh")
  (subpath "{{.UserHome}}/.aws")
  (subpath "{{.UserHome}}/.gnupg")
  (subpath "{{.UserHome}}/.kube")
  (subpath "{{.UserHome}}/.config/gcloud"))

;; Fallback defense-in-depth regex for non-standard user profiles
(deny file-read* file-write*
  (regex #"^/(Users|home)/[^/]+/\.(ssh|aws|gnupg|kube|config/gcloud)"))

;; Block access to launchd listeners in /tmp (V-10: ssh-agent socket protection)
(deny file-read* file-write*
  (regex #"^(/private)?/tmp/com\.apple\.launchd\..*"))

;; Block Docker daemon socket (V-06: Localhost Pivoting)
(deny file-read* file-write*
  (literal "/var/run/docker.sock")
  (literal "/private/var/run/docker.sock"))

;; Mask project secret files in workspace (V-04)
(deny file-read*
  (subpath "{{.WorkspaceRoot}}/.env")
  (regex #"^{{.WorkspaceRootEscaped}}/\.env(\..+)?$")
  (regex #"^{{.WorkspaceRootEscaped}}/.*\.pem$")
  (regex #"^{{.WorkspaceRootEscaped}}/(id_rsa|id_ed25519).*$")
  (regex #"^{{.WorkspaceRootEscaped}}/secrets\.json$"))
{{range .ExtraDenyRead}}
(deny file-read* (subpath "{{.}}"))
{{end}}

;; 5. Filesystem Write Policy: Strictly confined to Workspace and Scratch (V-03)
(deny file-write*)

(allow file-write*
  (subpath "{{.WorkspaceRoot}}")
  (subpath "{{.ScratchDir}}"))
{{range .ExtraAllowWrite}}
(allow file-write* (subpath "{{.}}"))
{{end}}

;; Prevent Workspace poisoning: protect .git directory from modification (V-03)
(deny file-write*
  (subpath "{{.WorkspaceRoot}}/.git"))
{{range .ExtraDenyWrite}}
(deny file-write* (subpath "{{.}}"))
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
`

// Generate renders the hardened Seatbelt Scheme profile string.
func (g *ProfileGenerator) Generate(p Params) (string, error) {
	if p.UserHome == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return "", fmt.Errorf("seatbelt: failed to get user home directory: %w", err)
		}
		p.UserHome = home
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

	expandPath := func(paths []string) []string {
		var out []string
		for _, raw := range paths {
			cleaned := strings.TrimSpace(raw)
			if strings.HasPrefix(cleaned, "~/") {
				cleaned = filepath.Join(p.UserHome, cleaned[2:])
			}
			out = append(out, cleaned)
		}
		return out
	}

	p.ExtraAllowRead = expandPath(p.ExtraAllowRead)
	p.ExtraAllowWrite = expandPath(p.ExtraAllowWrite)
	p.ExtraDenyRead = expandPath(p.ExtraDenyRead)
	p.ExtraDenyWrite = expandPath(p.ExtraDenyWrite)

	// Escape WorkspaceRoot for regex use
	p.WorkspaceRootEscaped = regexp.QuoteMeta(p.WorkspaceRoot)

	tmpl, err := template.New("seatbelt").Parse(profileTemplate)
	if err != nil {
		return "", fmt.Errorf("seatbelt: failed to parse template: %w", err)
	}

	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, p); err != nil {
		return "", fmt.Errorf("seatbelt: failed to execute template: %w", err)
	}

	return buf.String(), nil
}
