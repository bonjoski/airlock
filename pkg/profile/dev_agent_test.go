package profile

import (
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

func TestDevAgentSeatbeltGeneration(t *testing.T) {
	p := seatbelt.Params{
		UserHome:      "/Users/devuser",
		WorkspaceRoot: "/Users/devuser/code/project",
		ScratchDir:    "/tmp/airlock-scratch",
		ProxyPort:     8080,
	}

	sb, err := GenerateDevAgentSeatbelt(p)
	if err != nil {
		t.Fatalf("GenerateDevAgentSeatbelt failed: %v", err)
	}

	for _, denied := range []string{
		"/Users/devuser/.ssh",
		"/Users/devuser/.aws",
		"/Users/devuser/.gnupg",
		"/Users/devuser/.config/gh",
		"/System/Volumes/Data/Users/devuser/.ssh",
	} {
		if !strings.Contains(sb, denied) {
			t.Errorf("Missing denial in Seatbelt profile for %s", denied)
		}
	}

	if !strings.Contains(sb, "(deny process-info* (target others))") {
		t.Error("Missing process-info denial in Seatbelt profile")
	}
}

func TestDevAgentLandlockRuleset(t *testing.T) {
	cfg := landlock.Config{
		WorkspaceRoot: "/home/devuser/code/project",
		ScratchDir:    "/tmp/airlock-scratch",
		UserHome:      "/home/devuser",
	}

	rs := BuildDevAgentLandlock(cfg)
	if rs == nil {
		t.Fatal("BuildDevAgentLandlock returned nil")
	}

	for _, d := range DevAgentDefaultDenyPaths {
		found := false
		for _, rd := range rs.DenyPaths {
			if rd == d {
				found = true
				break
			}
		}
		if !found {
			t.Errorf("Landlock ruleset missing deny path %s", d)
		}
	}
}

func TestAugmentBwrapArgsForDevAgent(t *testing.T) {
	args := []string{"--unshare-user"}
	augmented := AugmentBwrapArgsForDevAgent(args, "/home/devuser", "/tmp/airlock-mask")

	hasCapDrop := false
	hasProcSys := false
	hasSSHMask := false

	for i, a := range augmented {
		if a == "--cap-drop" && i+1 < len(augmented) && augmented[i+1] == "ALL" {
			hasCapDrop = true
		}
		if a == "/proc/sys" {
			hasProcSys = true
		}
		if a == "/home/devuser/.ssh" {
			hasSSHMask = true
		}
	}

	if !hasCapDrop {
		t.Error("Missing --cap-drop ALL in augmented bwrap args")
	}
	if !hasProcSys {
		t.Error("Missing /proc/sys masking in augmented bwrap args")
	}
	if !hasSSHMask {
		t.Error("Missing /home/devuser/.ssh masking in augmented bwrap args")
	}
}
