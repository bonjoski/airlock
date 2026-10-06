package doctor

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func TestDoctor_RunAllChecks(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	report, err := RunAllChecks(ctx, tempDir)
	if err != nil {
		t.Fatalf("RunAllChecks failed: %v", err)
	}

	if report == nil {
		t.Fatal("Expected non-nil report")
	}

	if report.Platform == "" {
		t.Error("Report.Platform is empty")
	}

	if len(report.Results) == 0 {
		t.Fatal("Expected at least one diagnostic check result")
	}

	for _, res := range report.Results {
		if res.ID == "" {
			t.Errorf("Result has empty ID: %+v", res)
		}
		if res.Category == "" {
			t.Errorf("Result %s has empty Category", res.ID)
		}
		if res.Title == "" {
			t.Errorf("Result %s has empty Title", res.ID)
		}
		if res.Status != StatusPass && res.Status != StatusWarn && res.Status != StatusFail {
			t.Errorf("Result %s has invalid Status: %q", res.ID, res.Status)
		}
	}

	if report.Passed+report.Warnings+report.Failures != len(report.Results) {
		t.Errorf("Status count mismatch: %d passed, %d warnings, %d failures vs %d total results",
			report.Passed, report.Warnings, report.Failures, len(report.Results))
	}
}

func TestDoctor_CheckPlatformSandbox_Darwin(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       tempDir,
		GOOS:          "darwin",
		GOARCH:        "arm64",
	}

	results := CheckPlatformSandbox(ctx, opts)
	if len(results) < 2 {
		t.Fatalf("Expected at least 2 checks for darwin, got %d", len(results))
	}

	var foundExec, foundProfile bool
	for _, res := range results {
		if res.ID == "sandbox-seatbelt-exec" {
			foundExec = true
			if runtime.GOOS == "darwin" && res.Status != StatusPass {
				t.Errorf("Expected sandbox-seatbelt-exec to pass on macOS host, got %s (%s)", res.Status, res.Details)
			}
		}
		if res.ID == "sandbox-seatbelt-profile" {
			foundProfile = true
			if res.Status != StatusPass {
				t.Errorf("Expected sandbox-seatbelt-profile to pass, got %s: %s", res.Status, res.Details)
			}
		}
	}

	if !foundExec {
		t.Error("Missing sandbox-seatbelt-exec check")
	}
	if !foundProfile {
		t.Error("Missing sandbox-seatbelt-profile check")
	}
}

func TestDoctor_CheckPlatformSandbox_Linux(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       tempDir,
		GOOS:          "linux",
		GOARCH:        "amd64",
	}

	results := CheckPlatformSandbox(ctx, opts)
	if len(results) < 3 {
		t.Fatalf("Expected at least 3 checks for linux, got %d", len(results))
	}

	var foundBwrap, foundUserns, foundSeccomp bool
	for _, res := range results {
		switch res.ID {
		case "sandbox-bwrap":
			foundBwrap = true
		case "sandbox-userns":
			foundUserns = true
		case "sandbox-seccomp":
			foundSeccomp = true
			if res.Status != StatusPass {
				t.Errorf("Expected pure-Go seccomp compilation for linux/amd64 to pass, got %s: %s", res.Status, res.Details)
			}
		}
	}

	if !foundBwrap {
		t.Error("Missing sandbox-bwrap check")
	}
	if !foundUserns {
		t.Error("Missing sandbox-userns check")
	}
	if !foundSeccomp {
		t.Error("Missing sandbox-seccomp check")
	}
}

func TestDoctor_CheckPlatformSandbox_Windows(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       tempDir,
		GOOS:          "windows",
		GOARCH:        "amd64",
	}

	results := CheckPlatformSandbox(ctx, opts)
	if len(results) == 0 {
		t.Fatal("Expected results for Windows platform")
	}

	if results[0].Status != StatusPass {
		t.Errorf("Expected StatusPass for Windows, got %s", results[0].Status)
	}
	if !strings.Contains(results[0].Title, "Windows Job Object") {
		t.Errorf("Expected title to mention Windows Job Object, got %s", results[0].Title)
	}
}

func TestDoctor_CheckPlatformSandbox_UnsupportedOS(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       tempDir,
		GOOS:          "solaris",
		GOARCH:        "amd64",
	}

	results := CheckPlatformSandbox(ctx, opts)
	if len(results) == 0 {
		t.Fatal("Expected results for unsupported OS")
	}

	if results[0].Status != StatusFail {
		t.Errorf("Expected StatusFail for unsupported OS, got %s", results[0].Status)
	}
	if !strings.Contains(results[0].Details, "solaris") {
		t.Errorf("Expected details to mention solaris, got %s", results[0].Details)
	}
}

func TestDoctor_CheckStoragePermissions(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "mock_home")
	_ = os.Mkdir(homeDir, 0755)

	// Create caches
	_ = os.Mkdir(filepath.Join(homeDir, ".npm"), 0755)
	_ = os.MkdirAll(filepath.Join(homeDir, ".cache", "pip"), 0755)
	_ = os.MkdirAll(filepath.Join(homeDir, ".cargo", "registry"), 0755)

	opts := Options{
		HomeDir:     homeDir,
		ScratchBase: tempDir,
	}

	results := CheckStoragePermissions(ctx, opts)
	for _, res := range results {
		if res.Status == StatusFail {
			t.Errorf("Check %s unexpectedly failed: %s (%s)", res.ID, res.Details, res.Recommendation)
		}
	}

	// Verify ~/.airlock dir was created
	airlockDir := filepath.Join(homeDir, ".airlock")
	if info, err := os.Stat(airlockDir); err != nil || !info.IsDir() {
		t.Errorf("Expected %s to exist as directory", airlockDir)
	}
}

func TestDoctor_CheckStoragePermissions_Failure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows directories do not support POSIX read-only mode bits")
	}

	ctx := context.Background()
	tempDir := t.TempDir()

	// Create an unwritable home directory
	unwritableHome := filepath.Join(tempDir, "read_only_home")
	_ = os.Mkdir(unwritableHome, 0555)
	defer func() { _ = os.Chmod(unwritableHome, 0755) }()

	opts := Options{
		HomeDir:     unwritableHome,
		ScratchBase: tempDir,
	}

	results := CheckStoragePermissions(ctx, opts)
	var airlockCheck *CheckResult
	for i, res := range results {
		if res.ID == "storage-airlock-dir" {
			airlockCheck = &results[i]
			break
		}
	}

	if airlockCheck == nil {
		t.Fatal("storage-airlock-dir check not found")
	}

	if airlockCheck.Status != StatusFail {
		t.Errorf("Expected StatusFail on unwritable home, got %s", airlockCheck.Status)
	}
}

func TestDoctor_CheckNetworkProxy(t *testing.T) {
	ctx := context.Background()
	results := CheckNetworkProxy(ctx, Options{})

	if len(results) < 2 {
		t.Fatalf("Expected at least 2 network checks, got %d", len(results))
	}

	for _, res := range results {
		if res.Status != StatusPass {
			t.Errorf("Network check %s failed: %s", res.ID, res.Details)
		}
	}
}

func TestDoctor_CheckToolchainShims(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()
	shimDir := filepath.Join(tempDir, "shims")

	sep := string(os.PathListSeparator)

	// Case 1: Shim dir not in PATH
	opts1 := Options{
		HomeDir: tempDir,
		ShimDir: shimDir,
		PathEnv: strings.Join([]string{"/usr/bin", "/bin"}, sep),
	}

	res1 := CheckToolchainShims(ctx, opts1)
	if len(res1) == 0 {
		t.Fatal("Expected toolchain shim checks")
	}

	var pathCheck1 *CheckResult
	for _, r := range res1 {
		if r.ID == "shims-path-configured" {
			pathCheck1 = &r
			break
		}
	}
	if pathCheck1 == nil || pathCheck1.Status != StatusWarn {
		t.Errorf("Expected StatusWarn when shim dir not in PATH, got %+v", pathCheck1)
	}

	// Case 2: Shim dir in PATH
	opts2 := Options{
		HomeDir: tempDir,
		ShimDir: shimDir,
		PathEnv: strings.Join([]string{"/usr/bin", shimDir, "/bin"}, sep),
	}

	res2 := CheckToolchainShims(ctx, opts2)
	var pathCheck2 *CheckResult
	for _, r := range res2 {
		if r.ID == "shims-path-configured" {
			pathCheck2 = &r
			break
		}
	}
	if pathCheck2 == nil || pathCheck2.Status != StatusPass {
		t.Errorf("Expected StatusPass when shim dir in PATH, got %+v", pathCheck2)
	}
}

func TestDoctor_CheckDeclarativeConfig(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	// 1. No config -> WARN
	resNoConfig := CheckDeclarativeConfig(ctx, Options{WorkspaceRoot: tempDir})
	if len(resNoConfig) != 1 || resNoConfig[0].Status != StatusWarn {
		t.Errorf("Expected StatusWarn for missing config, got %+v", resNoConfig)
	}

	// 2. Valid config -> PASS
	validCfg := filepath.Join(tempDir, "airlock.yaml")
	_ = os.WriteFile(validCfg, []byte("version: \"1\"\nmode: \"strict\"\n"), 0644)

	resValid := CheckDeclarativeConfig(ctx, Options{WorkspaceRoot: tempDir})
	if len(resValid) != 1 || resValid[0].Status != StatusPass {
		t.Errorf("Expected StatusPass for valid config, got %+v", resValid)
	}

	// 3. Config with security guardrail alerts -> WARN
	guardrailCfg := filepath.Join(tempDir, "airlock.yaml")
	_ = os.WriteFile(guardrailCfg, []byte(`version: "1"
mode: "strict"
filesystem:
  allow_read:
    - "~/.ssh"
`), 0644)

	resGuardrail := CheckDeclarativeConfig(ctx, Options{WorkspaceRoot: tempDir})
	if len(resGuardrail) != 1 || resGuardrail[0].Status != StatusWarn {
		t.Errorf("Expected StatusWarn for guardrail alert config, got %+v", resGuardrail)
	}

	// 4. Broken YAML syntax -> FAIL
	brokenCfg := filepath.Join(tempDir, "airlock.yaml")
	_ = os.WriteFile(brokenCfg, []byte("version: [broken yaml: : :"), 0644)

	resBroken := CheckDeclarativeConfig(ctx, Options{WorkspaceRoot: tempDir})
	if len(resBroken) != 1 || resBroken[0].Status != StatusFail {
		t.Errorf("Expected StatusFail for broken config syntax, got %+v", resBroken)
	}
}

func TestDoctor_ReportFormatting(t *testing.T) {
	report := &Report{
		Timestamp:     time.Now().UTC(),
		Platform:      "darwin/arm64",
		WorkspaceRoot: "/mock/workspace",
		Healthy:       true,
		Passed:        3,
		Warnings:      1,
		Failures:      0,
		Results: []CheckResult{
			{
				ID:       "sandbox-seatbelt-exec",
				Category: "Platform Sandbox Primitives",
				Status:   StatusPass,
				Title:    "macOS Seatbelt executable",
				Details:  "Found at /usr/bin/sandbox-exec",
			},
			{
				ID:             "shims-path-configured",
				Category:       "Toolchain Shims",
				Status:         StatusWarn,
				Title:          "Toolchain shims in $PATH",
				Details:        "Not in $PATH",
				Recommendation: "Add to ~/.zshrc",
			},
		},
	}

	// 1. JSON formatting
	jsonData, err := report.ToJSON()
	if err != nil {
		t.Fatalf("ToJSON failed: %v", err)
	}

	var parsed Report
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("Failed to unmarshal JSON report: %v", err)
	}
	if parsed.Platform != "darwin/arm64" || !parsed.Healthy {
		t.Errorf("Unexpected unmarshaled report: %+v", parsed)
	}

	// 2. Terminal formatting
	plainText := report.FormatTerminal(false)
	if !strings.Contains(plainText, "Airlock Doctor — System Diagnostics & Health Report") {
		t.Error("FormatTerminal missing banner")
	}
	if !strings.Contains(plainText, "Platform Sandbox Primitives") {
		t.Error("FormatTerminal missing category header")
	}
	if !strings.Contains(plainText, "✓ PASS sandbox-seatbelt-exec") {
		t.Errorf("FormatTerminal missing pass item: %s", plainText)
	}
	if !strings.Contains(plainText, "Recommendation: Add to ~/.zshrc") {
		t.Errorf("FormatTerminal missing recommendation: %s", plainText)
	}

	colorText := report.FormatTerminal(true)
	if !strings.Contains(colorText, "\033[32m") {
		t.Error("FormatTerminal(true) missing ANSI color escape code")
	}
}
