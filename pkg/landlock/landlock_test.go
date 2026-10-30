package landlock

import (
	"runtime"
	"strings"
	"testing"
)

func TestBuildDevAgentRuleset(t *testing.T) {
	cfg := Config{
		WorkspaceRoot: "/home/user/project",
		ScratchDir:    "/tmp/airlock-test",
		UserHome:      "/home/user",
	}

	rs := BuildDevAgentRuleset(cfg)
	if rs == nil {
		t.Fatal("BuildDevAgentRuleset returned nil")
	}

	if rs.HandledAccessFS != AccessFSAll {
		t.Errorf("Expected HandledAccessFS to cover AccessFSAll, got %x", rs.HandledAccessFS)
	}

	// Verify that forbidden paths (~/.ssh, ~/.aws, etc.) are present in DenyPaths
	requiredDenies := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config/gh"}
	for _, req := range requiredDenies {
		found := false
		for _, d := range rs.DenyPaths {
			if d == req {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("DevAgent ruleset missing deny path: %s", req)
		}
	}

	// Verify that none of the allowed rules grant access to ~/.ssh or ~/.aws
	for _, rule := range rs.Rules {
		if strings.Contains(rule.Path, ".ssh") || strings.Contains(rule.Path, ".aws") {
			t.Errorf("SECURITY VULNERABILITY: Landlock rule explicitly permitted forbidden path: %s", rule.Path)
		}
	}

	// Verify workspace has AccessFSAll
	var workspaceRule *PathRule
	for _, r := range rs.Rules {
		if r.Path == cfg.WorkspaceRoot {
			workspaceRule = &r
			break
		}
	}
	if workspaceRule == nil {
		t.Errorf("Ruleset missing workspace root rule for %s", cfg.WorkspaceRoot)
	} else if workspaceRule.Access != AccessFSAll {
		t.Errorf("Workspace rule has access %x, expected %x", workspaceRule.Access, AccessFSAll)
	}
}

func TestApply_NonLinuxReturnsError(t *testing.T) {
	if runtime.GOOS == "linux" {
		t.Skip("Testing non-Linux behavior")
	}

	cfg := Config{
		WorkspaceRoot: "/tmp/ws",
	}
	rs := BuildDevAgentRuleset(cfg)
	err := Apply(rs)
	if err == nil {
		t.Fatal("Expected error on non-Linux platform, got nil")
	}
}
