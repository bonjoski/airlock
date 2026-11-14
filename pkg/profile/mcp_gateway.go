// Package profile provides centralized security definitions and profiles
// for specialized Airlock execution contexts, including dev-agent and mcp-gateway.
package profile

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

// MCPGatewayProfileName is the canonical profile identifier for MCP gateway and registry instances.
const MCPGatewayProfileName = "mcp-gateway"

// MCPGatewayDefaultDenyPaths enumerates sensitive host directories and credential files
// that must be strictly masked from MCP gateway and registry workloads (CVE-2026-125926).
var MCPGatewayDefaultDenyPaths = []string{
	"~/.ssh",
	"~/.aws",
	"~/.gnupg",
	"~/.kube",
	"~/.config/gh",
	"~/.config/gcloud",
	"~/.azure",
	"/var/run/docker.sock",
	".env",
	".env.*",
}

// GenerateMCPGatewaySeatbelt synthesizes a macOS Seatbelt profile for an MCP gateway,
// enforcing strict isolation of host credentials and anti-loopback controls.
func GenerateMCPGatewaySeatbelt(p seatbelt.Params) (string, error) {
	p.Profile = MCPGatewayProfileName
	p.AntiLoopback = true

	// Expand MCP gateway deny paths into ExtraDenyRead
	if p.UserHome != "" {
		for _, deny := range MCPGatewayDefaultDenyPaths {
			if strings.HasPrefix(deny, "~/") {
				p.ExtraDenyRead = append(p.ExtraDenyRead, filepath.Join(p.UserHome, deny[2:]))
			} else {
				p.ExtraDenyRead = append(p.ExtraDenyRead, deny)
			}
		}
	}

	gen := seatbelt.NewGenerator()
	return gen.Generate(p)
}

// BuildMCPGatewayLandlock synthesizes the Landlock LSM ruleset for Linux MCP gateways.
func BuildMCPGatewayLandlock(cfg landlock.Config) *landlock.Ruleset {
	rs := landlock.BuildDevAgentRuleset(cfg)
	if rs != nil {
		for _, p := range MCPGatewayDefaultDenyPaths {
			rs.DenyPaths = append(rs.DenyPaths, p)
		}
	}
	return rs
}

// AugmentBwrapArgsForMCPGateway appends Bubblewrap isolation flags required
// for MCP gateway isolation, including network capability dropping and credential masking.
func AugmentBwrapArgsForMCPGateway(args []string, userHome string, unreadableMask string) []string {
	// Drop all capabilities
	args = append(args, "--cap-drop", "ALL")

	if unreadableMask != "" {
		args = append(args,
			"--ro-bind-try", unreadableMask, "/proc/sys",
			"--ro-bind-try", unreadableMask, "/proc/kcore",
		)

		if userHome != "" {
			for _, deny := range MCPGatewayDefaultDenyPaths {
				if strings.HasPrefix(deny, "~/") {
					target := path.Join(filepath.ToSlash(userHome), deny[2:])
					args = append(args, "--ro-bind-try", unreadableMask, target)
				}
			}
		}
	}

	return args
}
