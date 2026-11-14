package profile

import (
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

func TestMCPGatewaySeatbeltGeneration(t *testing.T) {
	p := seatbelt.Params{
		UserHome:      "/Users/mcpuser",
		WorkspaceRoot: "/Users/mcpuser/gateway",
		ScratchDir:    "/tmp/airlock-scratch",
		ProxyPort:     9090,
	}

	sb, err := GenerateMCPGatewaySeatbelt(p)
	if err != nil {
		t.Fatalf("GenerateMCPGatewaySeatbelt failed: %v", err)
	}

	for _, denied := range []string{
		"/Users/mcpuser/.aws",
		"/Users/mcpuser/.ssh",
		"/Users/mcpuser/.kube",
		"/Users/mcpuser/.config/gcloud",
	} {
		if !strings.Contains(sb, denied) {
			t.Errorf("Missing denial in MCP gateway Seatbelt profile for %s", denied)
		}
	}

	// Verify anti-loopback denial rule is included
	if !strings.Contains(sb, `(to ip "localhost:*")`) {
		t.Errorf("Expected anti-loopback denial in MCP gateway profile")
	}
}

func TestMCPGatewayLandlockRuleset(t *testing.T) {
	cfg := landlock.Config{
		WorkspaceRoot: "/home/mcpuser/gateway",
		ScratchDir:    "/tmp/airlock-scratch",
		UserHome:      "/home/mcpuser",
	}

	rs := BuildMCPGatewayLandlock(cfg)
	if rs == nil {
		t.Fatal("BuildMCPGatewayLandlock returned nil")
	}

	for _, d := range MCPGatewayDefaultDenyPaths {
		found := false
		for _, rd := range rs.DenyPaths {
			if rd == d {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("MCP gateway Landlock missing deny path: %s", d)
		}
	}
}

func TestAugmentBwrapArgsForMCPGateway(t *testing.T) {
	baseArgs := []string{"bwrap", "--unshare-all"}
	augmented := AugmentBwrapArgsForMCPGateway(baseArgs, "/home/mcpuser", "/tmp/unreadable")

	hasCapDrop := false
	for i, arg := range augmented {
		if arg == "--cap-drop" && i+1 < len(augmented) && augmented[i+1] == "ALL" {
			hasCapDrop = true
			break
		}
	}

	if !hasCapDrop {
		t.Errorf("AugmentBwrapArgsForMCPGateway did not append --cap-drop ALL")
	}
}
