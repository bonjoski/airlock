// Package profile provides centralized security definitions and profiles
// for specialized Airlock execution contexts, including mcp hermetic wrapper.
package profile

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

// MCPProfileName is the canonical profile identifier for hermetic MCP wrapper executions.
const MCPProfileName = "mcp"

// MCPDefaultDenyPaths enumerates sensitive host directories and credential files
// that are strictly denied read/write access under the hermetic MCP profile.
var MCPDefaultDenyPaths = []string{
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

// GenerateMCPSeatbelt synthesizes the hardened macOS Seatbelt Scheme profile for MCP servers.
func GenerateMCPSeatbelt(p seatbelt.Params) (string, error) {
	p.Profile = MCPProfileName
	gen := seatbelt.NewGenerator()
	return gen.Generate(p)
}

// BuildMCPLandlock synthesizes the Landlock LSM ruleset for Linux MCP servers.
func BuildMCPLandlock(cfg landlock.Config) *landlock.Ruleset {
	rs := landlock.BuildDevAgentRuleset(cfg)
	if rs != nil {
		for _, p := range MCPDefaultDenyPaths {
			rs.DenyPaths = append(rs.DenyPaths, p)
		}
	}
	return rs
}

// AugmentBwrapArgsForMCP appends Bubblewrap isolation flags required
// for MCP server isolation, including capability dropping and credential masking.
func AugmentBwrapArgsForMCP(args []string, userHome string, unreadableMask string) []string {
	// Drop dangerous capabilities (CAP_SYS_ADMIN, CAP_PTRACE, CAP_NET_RAW)
	args = append(args, "--cap-drop", "ALL")

	if unreadableMask != "" {
		args = append(args,
			"--ro-bind-try", unreadableMask, "/proc/sys",
			"--ro-bind-try", unreadableMask, "/proc/kcore",
		)

		if userHome != "" {
			for _, deny := range MCPDefaultDenyPaths {
				if strings.HasPrefix(deny, "~/") {
					target := path.Join(filepath.ToSlash(userHome), deny[2:])
					args = append(args, "--ro-bind-try", unreadableMask, target)
				}
			}
		}
	}

	return args
}
