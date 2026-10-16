package config

import (
	"testing"
)

func TestGetBuiltinProfile_Agent(t *testing.T) {
	cfg, err := GetBuiltinProfile(ProfileAgent)
	if err != nil {
		t.Fatalf("expected agent profile to load, got error: %v", err)
	}

	if cfg.Mode != ModeStrict {
		t.Fatalf("expected ModeStrict, got %s", cfg.Mode)
	}

	// Verify required AI domains
	hasOpenAI := false
	hasAnthropic := false
	for _, d := range cfg.Network.AllowDomains {
		if d == "api.openai.com" {
			hasOpenAI = true
		}
		if d == "api.anthropic.com" {
			hasAnthropic = true
		}
	}
	if !hasOpenAI || !hasAnthropic {
		t.Fatalf("agent profile missing required AI domains: %v", cfg.Network.AllowDomains)
	}

	// Verify denied credential paths
	hasSSH := false
	hasAWS := false
	hasEnv := false
	for _, p := range cfg.Filesystem.DenyRead {
		if p == "~/.ssh" {
			hasSSH = true
		}
		if p == "~/.aws" {
			hasAWS = true
		}
		if p == ".env" {
			hasEnv = true
		}
	}
	if !hasSSH || !hasAWS || !hasEnv {
		t.Fatalf("agent profile missing required deny paths: %v", cfg.Filesystem.DenyRead)
	}

	// Verify vetting is enforced
	if !cfg.Vetting.Enable || !cfg.Vetting.Strict {
		t.Fatalf("agent profile must enforce strict Argus vetting: %v", cfg.Vetting)
	}
}

func TestGetBuiltinProfile_OtherProfiles(t *testing.T) {
	strict, err := GetBuiltinProfile(ProfileStrict)
	if err != nil || !strict.Vetting.Strict {
		t.Fatalf("strict profile failed: %v", err)
	}

	airgap, err := GetBuiltinProfile(ProfileAirgap)
	if err != nil || !airgap.Network.Airgap {
		t.Fatalf("airgap profile failed: %v", err)
	}

	def, err := GetBuiltinProfile(ProfileDefault)
	if err != nil || def == nil {
		t.Fatalf("default profile failed: %v", err)
	}

	_, err = GetBuiltinProfile("invalid_unknown_profile")
	if err == nil {
		t.Fatal("expected error for unknown profile, got nil")
	}
}

func TestMergeProfiles(t *testing.T) {
	base, _ := GetBuiltinProfile(ProfileAgent)
	overlay := &Config{
		Network: NetworkConfig{
			AllowDomains: []string{"custom.internal.ai"},
		},
		Filesystem: FilesystemConfig{
			AllowRead: []string{"/custom/read"},
		},
	}

	merged := MergeProfiles(base, overlay)
	if merged.Mode != ModeStrict {
		t.Fatalf("expected ModeStrict to be preserved, got %s", merged.Mode)
	}

	foundCustomDomain := false
	for _, d := range merged.Network.AllowDomains {
		if d == "custom.internal.ai" {
			foundCustomDomain = true
			break
		}
	}
	if !foundCustomDomain {
		t.Fatalf("expected custom domain in merged config: %v", merged.Network.AllowDomains)
	}
}
