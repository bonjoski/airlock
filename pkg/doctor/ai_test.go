package doctor

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
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

func TestGenerateAIAdvisory_AdversarialWireSecretRedaction(t *testing.T) {
	var outboundPayload string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		outboundPayload = string(body)
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"choices": []map[string]any{
				{
					"message":       map[string]any{"content": "Fix policy and rotate compromised tokens."},
					"finish_reason": "stop",
				},
			},
		})
	}))
	defer srv.Close()

	t.Setenv("GEMINI_API_KEY", "")
	t.Setenv("ANTHROPIC_API_KEY", "")
	t.Setenv("OPENAI_API_KEY", "test-dummy-key")
	t.Setenv("OPENAI_BASE_URL", srv.URL)
	t.Setenv("OLLAMA_HOST", "")

	rep := &Report{
		Timestamp:     time.Now(),
		Platform:      "darwin/arm64",
		WorkspaceRoot: "/workspace/adversarial",
		Healthy:       false,
		Failures:      1,
		Results: []CheckResult{
			{
				ID:             "env-leak",
				Category:       "sandbox",
				Status:         StatusFail,
				Title:          "Credential leak in policy",
				Details:        "aws=AKIA\u200bIOSFODNN7EXAMPLE pat=ghp_1234567890abcdefghijklmnopqrstuvwxyz raw=k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ",
				Recommendation: "Remove hardcoded secrets",
			},
		},
	}

	advisory, err := rep.GenerateAIAdvisory(context.Background())
	if err != nil {
		t.Fatalf("GenerateAIAdvisory failed: %v", err)
	}
	if !strings.Contains(advisory, "rotate compromised tokens") {
		t.Fatalf("unexpected advisory response: %q", advisory)
	}

	for _, forbidden := range []string{
		"AKIAIOSFODNN7EXAMPLE",
		"ghp_1234567890abcdefghijklmnopqrstuvwxyz",
		"k9J2m!xQ8$vP4zL7*wR1tY6#bN3cV5mZ",
	} {
		if strings.Contains(outboundPayload, forbidden) {
			t.Fatalf("outbound HTTP payload leaked secret %q: %s", forbidden, outboundPayload)
		}
	}
	if !strings.Contains(outboundPayload, "[SECRET_REF_") {
		t.Fatalf("expected redacted placeholder in outbound payload: %s", outboundPayload)
	}
}
