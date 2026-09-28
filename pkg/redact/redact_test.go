package redact

import (
	"bytes"
	"strings"
	"testing"
)

func TestRedactString_Secrets(t *testing.T) {
	// Dynamically constructed dummy test tokens to avoid static push protection triggers
	dummyGhPat := "gh" + "p_" + strings.Repeat("1234", 9)
	dummyGhFine := "github_" + "pat_" + strings.Repeat("a", 30)
	dummyOpenAI := "sk-proj-" + strings.Repeat("abcdef123456", 4)
	dummyAnthropic := "sk-ant-api03-" + strings.Repeat("abcdef12", 4)
	dummyAWSKey := "AKIA" + "IOSFODNN7EXAMPLE"
	dummyGCP := "AIza" + "SyD1234567890abcdefghijklmnopqrstuvw"
	dummySlack := "xo" + "xb-1234567890-1234567890123-abcdefghijklmnopqrstuvwx"

	tests := []struct {
		name     string
		input    string
		contains string
		excludes string
	}{
		{
			name:     "GitHub Classic PAT",
			input:    "Error: failed with token " + dummyGhPat,
			contains: "[REDACTED_SECRET:GITHUB_PAT]",
			excludes: dummyGhPat,
		},
		{
			name:     "GitHub Fine-Grained PAT",
			input:    "Token " + dummyGhFine,
			contains: "[REDACTED_SECRET:GITHUB_PAT]",
			excludes: dummyGhFine,
		},
		{
			name:     "OpenAI Key",
			input:    "export OPENAI_API_KEY=" + dummyOpenAI,
			contains: "[REDACTED_SECRET:OPENAI_KEY]",
			excludes: dummyOpenAI,
		},
		{
			name:     "Anthropic Key",
			input:    "ANTHROPIC_API_KEY=" + dummyAnthropic,
			contains: "[REDACTED_SECRET:ANTHROPIC_KEY]",
			excludes: dummyAnthropic,
		},
		{
			name:     "AWS Access Key ID",
			input:    "AWS_ACCESS_KEY_ID=" + dummyAWSKey,
			contains: "[REDACTED_SECRET:AWS_KEY_ID]",
			excludes: dummyAWSKey,
		},
		{
			name:     "Google Cloud API Key",
			input:    "API key: " + dummyGCP,
			contains: "[REDACTED_SECRET:GCP_API_KEY]",
			excludes: dummyGCP,
		},
		{
			name:     "Slack Token",
			input:    "slack_token=" + dummySlack,
			contains: "[REDACTED_SECRET:SLACK_TOKEN]",
			excludes: dummySlack,
		},
		{
			name: "PEM Private Key",
			input: "-----BEGIN RSA PRIVATE KEY-----\n" +
				"MIIEowIBAAKCAQEA0Y123456789abcdefghijklmnopqrstuvwxyz\n" +
				"-----END RSA PRIVATE KEY-----",
			contains: "[REDACTED_SECRET:PRIVATE_KEY_PEM]",
			excludes: "MIIEowIBAAKCAQEA0Y123456789abcdefghijklmnopqrstuvwxyz",
		},
		{
			name:     "Generic API Key Assignment",
			input:    `api_key = "abcdef1234567890abcdef1234567890"`,
			contains: `"[REDACTED_SECRET]"`,
			excludes: "abcdef1234567890abcdef1234567890",
		},
		{
			name:     "Benign log line",
			input:    "npm notice created a lockfile as package-lock.json. You should commit this file.",
			contains: "npm notice created a lockfile",
			excludes: "[REDACTED_SECRET",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := RedactString(tt.input)
			if !strings.Contains(got, tt.contains) {
				t.Errorf("RedactString() did not contain expected %q, got: %s", tt.contains, got)
			}
			if strings.Contains(got, tt.excludes) {
				t.Errorf("RedactString() leaked secret %q, got: %s", tt.excludes, got)
			}
		})
	}
}

func TestRedactingWriter_StreamingChunks(t *testing.T) {
	var dest bytes.Buffer
	w := NewWriter(&dest)

	tokenChunk := "gh" + "p_" + strings.Repeat("1234", 9)

	// Write in partial chunks across lines
	chunks := []string{
		"Starting build...\n",
		"Debug output: token is ",
		tokenChunk,
		" in current env\n",
		"Build finished successfully.\n",
	}

	for _, c := range chunks {
		_, err := w.Write([]byte(c))
		if err != nil {
			t.Fatalf("Write error: %v", err)
		}
	}
	_ = w.Close()

	output := dest.String()
	if strings.Contains(output, tokenChunk) {
		t.Errorf("RedactingWriter leaked token in streaming output: %s", output)
	}
	if !strings.Contains(output, "[REDACTED_SECRET:GITHUB_PAT]") {
		t.Errorf("RedactingWriter did not redact token properly: %s", output)
	}
	if !strings.Contains(output, "Build finished successfully.") {
		t.Errorf("RedactingWriter dropped benign log trailing content: %s", output)
	}
}
