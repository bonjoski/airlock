package doctor

import (
	"context"
	"fmt"
	"strings"

	"github.com/bonjoski/airlock/internal/aiadvisor"
)

// GenerateAIAdvisory uses Airlock's built-in client-side secret redactor to scrub
// credentials and high-entropy tokens, enforces a fail-closed wire guard check,
// and invokes the configured BYO-AI provider to provide actionable root-cause
// diagnosis and remediation steps for doctor warnings and failures.
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

	// 1. Client-side pre-flight secret redaction (regex + Shannon entropy + Unicode smuggling normalization)
	redactor := aiadvisor.NewRedactor(aiadvisor.DefaultRedactorConfig())
	redacted, tm, err := redactor.Redact(raw.String())
	if err != nil {
		return "", fmt.Errorf("failed to redact diagnostic prompt: %w", err)
	}
	defer tm.Zeroize()

	// 2. Fail-closed wire guard check
	if err := redactor.FailClosedWireGuard([]byte(redacted)); err != nil {
		return "", fmt.Errorf("wire guard blocked diagnostic payload: %w", err)
	}

	// 3. BYO-AI inference call
	prov := aiadvisor.NewProviderFromEnv()
	resp, err := prov.Complete(ctx, aiadvisor.Request{
		Model: "auto",
		Messages: []aiadvisor.Message{
			{Role: aiadvisor.RoleUser, Content: redacted},
		},
	})
	if err != nil {
		return "", fmt.Errorf("ai inference failed: %w", err)
	}

	return resp.Content, nil
}
