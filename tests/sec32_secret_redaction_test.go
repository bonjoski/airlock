package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/mcp"
	"github.com/bonjoski/airlock/pkg/redact"
	"github.com/bonjoski/airlock/pkg/sandbox"
)

// TestSEC32_SecretRedaction verifies invariant V-24:
// In-stream output generated during sandboxed execution or returned by MCP airlock_exec
// is automatically scanned and dynamically redacted to prevent accidental exfiltration or display of API keys and tokens.
func TestSEC32_SecretRedaction(t *testing.T) {
	tmpDir, err := os.MkdirTemp("", "airlock-sec32-*")
	if err != nil {
		t.Fatalf("Failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// 1. Verify direct Sandbox Engine execution with RedactingWriter
	t.Run("SandboxEngine_RedactsLeakedTokensInStdout", func(t *testing.T) {
		var rawOut bytes.Buffer
		redactingWriter := redact.NewWriter(&rawOut)

		opts := sandbox.Options{
			WorkspaceRoot:  tmpDir,
			Airgap:         true,
			NonInteractive: true,
			Stdout:         redactingWriter,
			Stderr:         redactingWriter,
		}

		engine, err := sandbox.NewEngine(opts)
		if err != nil {
			t.Fatalf("Failed to initialize sandbox engine: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		fakeToken := "gh" + "p_" + strings.Repeat("9876", 9)
		exitCode, err := engine.Execute(ctx, []string{"echo", "leaked token: " + fakeToken})
		_ = redactingWriter.Close()

		if err != nil {
			t.Fatalf("Engine execute failed: %v", err)
		}
		if exitCode != 0 {
			t.Fatalf("Expected exit code 0, got %d", exitCode)
		}

		captured := rawOut.String()
		if strings.Contains(captured, fakeToken) {
			t.Fatalf("SEC-32 INVARIANT VIOLATION: Raw token leaked in sandboxed stdout: %s", captured)
		}
		if !strings.Contains(captured, "[REDACTED_SECRET:GITHUB_PAT]") {
			t.Fatalf("SEC-32 INVARIANT VIOLATION: Mask tag [REDACTED_SECRET:GITHUB_PAT] missing from output: %s", captured)
		}
	})

	// 2. Verify MCP Tool Execution (airlock_exec) redacts leaked tokens before sending to AI Agent
	t.Run("MCPTool_ExecRedactsSensitiveTokens", func(t *testing.T) {
		toolHandler := mcp.NewDefaultToolHandler()

		fakeOpenAI := "sk-proj-" + strings.Repeat("1234567890ab", 4)
		execPayload, _ := json.Marshal(map[string]interface{}{
			"command":   "echo export OPENAI_API_KEY=" + fakeOpenAI,
			"workspace": tmpDir,
			"airgap":    true,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := toolHandler.HandleExec(ctx, execPayload)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}
		if len(result.Content) == 0 {
			t.Fatalf("Expected non-empty MCP tool content")
		}

		responseText := result.Content[0].Text
		if strings.Contains(responseText, fakeOpenAI) {
			t.Fatalf("SEC-32 INVARIANT VIOLATION: OpenAI secret leaked in MCP airlock_exec response: %s", responseText)
		}
		if !strings.Contains(responseText, "[REDACTED_SECRET:OPENAI_KEY]") {
			t.Fatalf("SEC-32 INVARIANT VIOLATION: OpenAI mask tag missing from MCP response: %s", responseText)
		}
	})

	// 3. Verify Multiple Token Classes Redaction
	t.Run("MultiClass_TokenRedactionCoverage", func(t *testing.T) {
		dummyAWSKey := "AKIA" + "IOSFODNN7EXAMPLE"
		dummyGCP := "AIza" + "SyD1234567890abcdefghijklmnopqrstuvw"
		dummyAnthropic := "sk-ant-api03-" + strings.Repeat("abcdef12", 4)

		leakScript := filepath.Join(tmpDir, "leak.sh")
		scriptContent := "#!/bin/sh\n" +
			"echo \"AWS_ACCESS_KEY_ID=" + dummyAWSKey + "\"\n" +
			"echo \"" + dummyGCP + "\"\n" +
			"echo \"ANTHROPIC_API_KEY=" + dummyAnthropic + "\"\n"

		if err := os.WriteFile(leakScript, []byte(scriptContent), 0755); err != nil {
			t.Fatalf("Failed to write leak script: %v", err)
		}

		toolHandler := mcp.NewDefaultToolHandler()
		execPayload, _ := json.Marshal(map[string]interface{}{
			"command":   "/bin/sh " + leakScript,
			"workspace": tmpDir,
			"airgap":    true,
		})

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		result, err := toolHandler.HandleExec(ctx, execPayload)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}

		responseText := result.Content[0].Text
		if strings.Contains(responseText, dummyAWSKey) ||
			strings.Contains(responseText, dummyGCP) ||
			strings.Contains(responseText, dummyAnthropic) {
			t.Fatalf("SEC-32 INVARIANT VIOLATION: Multi-class secrets leaked in response: %s", responseText)
		}

		if !strings.Contains(responseText, "[REDACTED_SECRET:AWS_KEY_ID]") ||
			!strings.Contains(responseText, "[REDACTED_SECRET:GCP_API_KEY]") ||
			!strings.Contains(responseText, "[REDACTED_SECRET:ANTHROPIC_KEY]") {
			t.Fatalf("SEC-32 INVARIANT VIOLATION: Required redaction tags missing: %s", responseText)
		}
	})
}
