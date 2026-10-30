// Package profile provides centralized definitions and security policies
// for specialized Airlock execution profiles, including dev-agent.
package profile

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

// DevAgentProfileName is the canonical profile identifier for autonomous coding agents.
const DevAgentProfileName = "dev-agent"

// DevAgentDefaultDenyPaths enumerates sensitive host directories and credential files
// that are strictly denied read/write access under the dev-agent profile.
var DevAgentDefaultDenyPaths = []string{
	"~/.ssh",
	"~/.aws",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gh",
	"~/.config/gcloud",
	"/var/run/docker.sock",
	".env",
	".env.*",
}

// DevAgentDefaultSecrets lists credentials dynamically leased via Locksmith ETX for dev-agent.
var DevAgentDefaultSecrets = []string{
	"OPENAI_API_KEY",
	"ANTHROPIC_API_KEY",
	"GITHUB_TOKEN",
	"GEMINI_API_KEY",
}

// GenerateDevAgentSeatbelt synthesizes the hardened macOS Seatbelt Scheme profile.
func GenerateDevAgentSeatbelt(p seatbelt.Params) (string, error) {
	p.Profile = DevAgentProfileName
	gen := seatbelt.NewGenerator()
	return gen.Generate(p)
}

// BuildDevAgentLandlock synthesizes the Landlock LSM ruleset for Linux.
func BuildDevAgentLandlock(cfg landlock.Config) *landlock.Ruleset {
	return landlock.BuildDevAgentRuleset(cfg)
}

// AugmentBwrapArgsForDevAgent appends extra Bubblewrap isolation flags required
// for the dev-agent profile, including capability dropping and credential masking.
func AugmentBwrapArgsForDevAgent(args []string, userHome string, unreadableMask string) []string {
	// Drop dangerous capabilities (CAP_SYS_ADMIN, CAP_PTRACE, CAP_NET_RAW)
	args = append(args,
		"--cap-drop", "ALL",
	)

	// Mask /proc/sys and /proc/kcore if unreadableMask is provided
	if unreadableMask != "" {
		args = append(args,
			"--ro-bind-try", unreadableMask, "/proc/sys",
			"--ro-bind-try", unreadableMask, "/proc/kcore",
		)

		// Mask host credential directories in user's home
		if userHome != "" {
			for _, deny := range DevAgentDefaultDenyPaths {
				if strings.HasPrefix(deny, "~/") {
					target := path.Join(filepath.ToSlash(userHome), deny[2:])
					args = append(args, "--ro-bind-try", unreadableMask, target)
				}
			}
		}
	}

	return args
}
