package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/vet"
)

func TestRunVet_StrictPassesCleanWorkspace(t *testing.T) {
	ws := t.TempDir()
	var stdout, stderr bytes.Buffer
	code := runVet([]string{"--strict", "--dir", ws}, &stdout, &stderr)
	if code != 0 {
		t.Fatalf("expected exit 0 on clean workspace, got %d (stdout=%q stderr=%q)", code, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "Siren Profile:  PASS") {
		t.Errorf("expected Siren PASS confirmation in stdout, got %q", stdout.String())
	}
}

func TestRunVet_StrictBlocksMisconfiguredConfigWithExit30(t *testing.T) {
	ws := t.TempDir()
	badYAML := `version: "1"
mode: permissive
network:
  allow_domains:
    - "*"
filesystem:
  allow_read:
    - "~/.ssh"
`
	if err := os.WriteFile(filepath.Join(ws, ".airlock.yaml"), []byte(badYAML), 0644); err != nil {
		t.Fatalf("write .airlock.yaml: %v", err)
	}

	// Default calm FixForwardError text output
	var stdout, stderr bytes.Buffer
	code := runVet([]string{"--strict", "--dir", ws}, &stdout, &stderr)
	if code != vet.SirenExitCode {
		t.Fatalf("expected exit %d, got %d (stdout=%q stderr=%q)", vet.SirenExitCode, code, stdout.String(), stderr.String())
	}
	errOut := stderr.String()
	if !strings.Contains(errOut, "⚠ airlock:") || !strings.Contains(errOut, "Fix:") || !strings.Contains(errOut, "Why:") {
		t.Errorf("expected calm UB-CLI-v2 FixForwardError output on stderr, got %q", errOut)
	}

	// Structured --json output
	stdout.Reset()
	stderr.Reset()
	code = runVet([]string{"--strict", "--dir", ws, "--json"}, &stdout, &stderr)
	if code != vet.SirenExitCode {
		t.Fatalf("expected exit %d in --json mode, got %d", vet.SirenExitCode, code)
	}
	var parsed struct {
		ExitCode       int                `json:"exit_code"`
		BlockExecution bool               `json:"block_execution"`
		SirenFindings  []vet.SirenFinding `json:"siren_findings"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON from --strict --json: %v (raw=%q)", err, stdout.String())
	}
	if parsed.ExitCode != vet.SirenExitCode || !parsed.BlockExecution || len(parsed.SirenFindings) == 0 {
		t.Fatalf("unexpected JSON payload: %+v", parsed)
	}
}

func TestRunVet_StrictBlocksWeakSBPLFileWithExit30(t *testing.T) {
	ws := t.TempDir()
	weakSBPL := filepath.Join(ws, "weak.sb")
	content := "(version 1)\n(deny default)\n(allow file-read*)\n(allow network*)\n"
	if err := os.WriteFile(weakSBPL, []byte(content), 0644); err != nil {
		t.Fatalf("write weak.sb: %v", err)
	}

	var stdout, stderr bytes.Buffer
	code := runVet([]string{"--strict", "--dir", ws, "--sbpl", weakSBPL, "--why"}, &stdout, &stderr)
	if code != vet.SirenExitCode {
		t.Fatalf("expected exit %d on weak SBPL, got %d", vet.SirenExitCode, code)
	}
	if !strings.Contains(stderr.String(), "AIRLOCK-SIREN-") {
		t.Errorf("expected Siren rule IDs in --why deep dive, got %q", stderr.String())
	}
}
