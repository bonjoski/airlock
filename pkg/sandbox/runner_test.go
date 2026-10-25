package sandbox

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestRunner_Interface(t *testing.T) {
	var runner Runner = NewRunner()
	if runner == nil {
		t.Fatal("expected NewRunner() to return non-nil Runner")
	}
}

func TestRunner_EmptyCommand(t *testing.T) {
	runner := NewRunner()
	res, err := runner.Execute(context.Background(), nil, SandboxOpts{})
	if err == nil {
		t.Fatal("expected error when executing empty command, got nil")
	}
	if res != nil {
		t.Fatalf("expected nil result on invalid command, got %v", res)
	}
}

func TestRunner_Execute_StandardProfile(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("skipping runner execution test on unsupported OS")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	if err := os.Mkdir(workspace, 0755); err != nil {
		t.Fatalf("failed to create temp workspace: %v", err)
	}

	runner := NewRunner()
	ctx := context.Background()

	opts := SandboxOpts{
		Profile:        "standard",
		WorkspaceRoot:  workspace,
		Airgap:         true,
		NonInteractive: true,
	}

	echoBin := "/bin/echo"
	if _, err := os.Stat(echoBin); err != nil {
		echoBin = "echo"
	}

	res, err := runner.Execute(ctx, []string{echoBin, "standard_profile_test_output"}, opts)
	if err != nil {
		t.Fatalf("runner.Execute failed: %v", err)
	}

	if !res.Success() {
		t.Fatalf("expected res.Success() == true, got code=%d, err=%s", res.ExitCode, res.Error)
	}

	if !strings.Contains(res.Stdout, "standard_profile_test_output") {
		t.Fatalf("expected stdout to contain test string, got: %q", res.Stdout)
	}

	if res.DurationMs <= 0 {
		t.Errorf("expected DurationMs > 0, got %d", res.DurationMs)
	}

	// Verify standard profile allow domains were populated
	hasGoProxy := false
	hasCrates := false
	hasNpm := false
	hasPypi := false
	for _, d := range res.AllowedDomains {
		if d == "proxy.golang.org" {
			hasGoProxy = true
		}
		if d == "crates.io" {
			hasCrates = true
		}
		if d == "registry.npmjs.org" {
			hasNpm = true
		}
		if d == "pypi.org" {
			hasPypi = true
		}
	}

	if !hasGoProxy || !hasCrates || !hasNpm || !hasPypi {
		t.Fatalf("standard profile domains missing required modern language runtimes: %v", res.AllowedDomains)
	}
}

func TestRunner_OutputStreaming(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("skipping runner stream test on unsupported OS")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var streamedStdout bytes.Buffer
	var streamedStderr bytes.Buffer

	opts := SandboxOpts{
		WorkspaceRoot:  workspace,
		Airgap:         true,
		NonInteractive: true,
		Stdout:         &streamedStdout,
		Stderr:         &streamedStderr,
	}

	echoBin := "/bin/echo"
	if _, err := os.Stat(echoBin); err != nil {
		echoBin = "echo"
	}

	res, err := Execute(context.Background(), []string{echoBin, "stream_test"}, opts)
	if err != nil {
		t.Fatalf("Execute failed: %v", err)
	}

	if res.ExitCode != 0 {
		t.Errorf("expected exit code 0, got %d", res.ExitCode)
	}

	// Both streamed buffer and captured res.Stdout should receive the output
	if !strings.Contains(streamedStdout.String(), "stream_test") {
		t.Errorf("expected streamedStdout to contain output, got: %q", streamedStdout.String())
	}
	if !strings.Contains(res.Stdout, "stream_test") {
		t.Errorf("expected res.Stdout to contain output, got: %q", res.Stdout)
	}
}
