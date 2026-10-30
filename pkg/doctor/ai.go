package doctor

import (
	"context"
	"fmt"
	"strings"

	"github.com/bonjoski/shield/pkg/provider"
	"github.com/bonjoski/shield/pkg/shield"
)

// GenerateAIAdvisory uses the sovereign Shield engine to redact any workstation paths
// or environment credentials, then invokes the AI provider to provide actionable
// root-cause diagnosis and remediation steps for doctor warnings and failures.
func (r *Report) GenerateAIAdvisory(ctx context.Context) (string, error) {
	if ctx == nil {
		ctx = context.Background()
	}

	var raw strings.Builder
	raw.WriteString(fmt.Sprintf("Airlock Diagnostic Report:\nPlatform: %s\nHealthy: %v\nPassed: %d, Warnings: %d, Failures: %d\n\n",
		r.Platform, r.Healthy, r.Passed, r.Warnings, r.Failures))

	if r.Healthy && r.Warnings == 0 {
		raw.WriteString("All security checks passed. No kernel sandbox or shim failures detected.")
	} else {
		raw.WriteString("Issues detected:\n")
		for _, res := range r.Results {
			if res.Status != StatusPass {
				raw.WriteString(fmt.Sprintf("- [%s] %s: %s (Details: %s, Recommendation: %s)\n",
					res.Status, res.ID, res.Title, res.Details, res.Recommendation))
			}
		}
	}

	// 1. Redact via sovereign Shield engine
	engine := shield.NewEngine(shield.DefaultConfig())
	redacted, _, err := engine.Redact(raw.String())
	if err != nil {
		return "", fmt.Errorf("failed to redact diagnostic prompt: %w", err)
	}

	// 2. Fail-closed wire guard check
	if err := engine.FailClosedWireGuard([]byte(redacted)); err != nil {
		return "", fmt.Errorf("wire guard blocked diagnostic payload: %w", err)
	}

	// 3. Inference call
	prov := provider.NewFromEnv()
	resp, err := prov.Complete(ctx, provider.Request{
		Model: "auto",
		Messages: []provider.Message{
			{Role: provider.RoleUser, Content: redacted},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ai inference failed: %w", err)
	}

	return resp.Content, nil
}
