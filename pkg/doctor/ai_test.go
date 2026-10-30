package doctor

import (
	"context"
	"strings"
	"testing"
	"time"
)

func TestGenerateAIAdvisory_Healthy(t *testing.T) {
	rep := &Report{
		Timestamp:     time.Now(),
		Platform:      "darwin/arm64",
		WorkspaceRoot: "/workspace/test",
		Healthy:       true,
		Passed:        5,
		Warnings:      0,
		Failures:      0,
	}

	advisory, err := rep.GenerateAIAdvisory(context.Background())
	if err != nil {
		t.Fatalf("expected nil error on healthy advisory, got: %v", err)
	}
	if advisory == "" {
		t.Fatal("expected non-empty advisory output")
	}
}

func TestGenerateAIAdvisory_WithFailuresAndShieldRedaction(t *testing.T) {
	rep := &Report{
		Timestamp:     time.Now(),
		Platform:      "linux/amd64",
		WorkspaceRoot: "/workspace/broken",
		Healthy:       false,
		Passed:        3,
		Warnings:      1,
		Failures:      1,
		Results: []CheckResult{
			{
				ID:             "kernel-seccomp",
				Category:       "sandbox",
				Status:         StatusFail,
				Title:          "Seccomp BPF filter rejected",
				Details:        "Unexpected secret in policy: AKIAIOSFODNN7EXAMPLE",
				Recommendation: "Fix seccomp BPF policy definition",
			},
			{
				ID:             "shim-permissions",
				Category:       "shims",
				Status:         StatusWarn,
				Title:          "Shim directory lacks strict 0700 permissions",
				Details:        "chmod 0755 detected",
				Recommendation: "Run chmod 0700 on ~/.airlock/shims",
			},
		},
	}

	advisory, err := rep.GenerateAIAdvisory(context.Background())
	if err != nil {
		t.Fatalf("GenerateAIAdvisory failed: %v", err)
	}

	// Verify the AWS secret in Details was shielded and not in the raw response
	if strings.Contains(advisory, "AKIAIOSFODNN7EXAMPLE") {
		t.Errorf("advisory leaked unredacted AWS secret: %s", advisory)
	}
}
