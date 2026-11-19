package landlock

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestIsDeniedPath(t *testing.T) {
	home, err := os.UserHomeDir()
	if err != nil {
		t.Skip("No home directory found")
	}

	denyPaths := []string{
		"~/.ssh",
		"~/.aws",
		"/etc/shadow",
		".env",
		".env.*",
	}

	cases := []struct {
		target   string
		expected bool
	}{
		{filepath.Join(home, ".ssh"), true},
		{filepath.Join(home, ".ssh", "id_rsa"), true},
		{filepath.Join(home, ".aws", "credentials"), true},
		{"/etc/shadow", true},
		{"/tmp/project/.env", true},
		{"/tmp/project/.env.production", true},
		{"/tmp/project/src/.env.local", true},
		{"/tmp/project/main.go", false},
		{"/usr/bin", false},
	}

	for _, c := range cases {
		got := IsDeniedPath(c.target, denyPaths)
		if got != c.expected {
			t.Errorf("IsDeniedPath(%q) = %v; expected %v", c.target, got, c.expected)
		}
	}
}

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

func TestMaskSupportedAccessFS(t *testing.T) {
	allFlags := uint64(AccessFSAll)

	// ABI 1: No AccessFSRefer (1<<13), no AccessFSTruncate (1<<14), no AccessFSIoctlDev (1<<15)
	v1 := MaskSupportedAccessFS(allFlags, 1)
	if v1&AccessFSRefer != 0 {
		t.Errorf("ABI v1 must not contain AccessFSRefer")
	}
	if v1&AccessFSTruncate != 0 {
		t.Errorf("ABI v1 must not contain AccessFSTruncate")
	}
	if v1&AccessFSIoctlDev != 0 {
		t.Errorf("ABI v1 must not contain AccessFSIoctlDev")
	}

	// ABI 2: Contains AccessFSRefer, but no AccessFSTruncate, no AccessFSIoctlDev
	v2 := MaskSupportedAccessFS(allFlags, 2)
	if v2&AccessFSRefer == 0 {
		t.Errorf("ABI v2 should contain AccessFSRefer")
	}
	if v2&AccessFSTruncate != 0 {
		t.Errorf("ABI v2 must not contain AccessFSTruncate")
	}
	if v2&AccessFSIoctlDev != 0 {
		t.Errorf("ABI v2 must not contain AccessFSIoctlDev")
	}

	// ABI 3/4: Contains AccessFSTruncate, but no AccessFSIoctlDev
	v3 := MaskSupportedAccessFS(allFlags, 3)
	if v3&AccessFSTruncate == 0 {
		t.Errorf("ABI v3 should contain AccessFSTruncate")
	}
	if v3&AccessFSIoctlDev != 0 {
		t.Errorf("ABI v3 must not contain AccessFSIoctlDev")
	}

	// ABI 5+: Contains all flags including AccessFSIoctlDev
	v5 := MaskSupportedAccessFS(allFlags, 5)
	if v5&AccessFSIoctlDev == 0 {
		t.Errorf("ABI v5 should contain AccessFSIoctlDev")
	}
	if v5 != allFlags {
		t.Errorf("ABI v5 should match allFlags (%x != %x)", v5, allFlags)
	}

	// Unsupported ABI (<=0)
	v0 := MaskSupportedAccessFS(allFlags, 0)
	if v0 != 0 {
		t.Errorf("ABI 0 should return 0, got %x", v0)
	}
}
