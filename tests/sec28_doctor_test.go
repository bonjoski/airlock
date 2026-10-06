package tests

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/doctor"
)

// TestSEC28_DoctorHealthyEnvironment verifies that doctor diagnoses a fully healthy
// workstation and workspace environment without false positive failures (SEC-28).
func TestSEC28_DoctorHealthyEnvironment(t *testing.T) {
	tempDir := t.TempDir()
	homeDir := filepath.Join(tempDir, "home")
	workspace := filepath.Join(tempDir, "workspace")
	scratchBase := filepath.Join(tempDir, "scratch")

	_ = os.Mkdir(homeDir, 0755)
	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratchBase, 0700)

	// Create valid airlock.yaml in workspace
	cfgPath := filepath.Join(workspace, "airlock.yaml")
	_ = os.WriteFile(cfgPath, []byte("version: \"1\"\nmode: \"strict\"\n"), 0644)

	// Add shim dir to PATH
	shimDir := filepath.Join(homeDir, ".airlock", "bin")
	_ = os.MkdirAll(shimDir, 0755)

	opts := doctor.Options{
		WorkspaceRoot: workspace,
		HomeDir:       homeDir,
		ScratchBase:   scratchBase,
		ShimDir:       shimDir,
		PathEnv:       shimDir + ":" + os.Getenv("PATH"),
	}

	report, err := doctor.RunChecks(context.Background(), opts)
	if err != nil {
		t.Fatalf("SEC-28 FAILED: RunChecks returned unexpected error: %v", err)
	}

	if !report.Healthy {
		t.Errorf("SEC-28 FAILED: Expected report to be Healthy, got failures: %d (warnings: %d)", report.Failures, report.Warnings)
		for _, r := range report.Results {
			if r.Status == doctor.StatusFail {
				t.Errorf("  Failed check: %s (%s): %s", r.ID, r.Title, r.Details)
			}
		}
	}

	if report.Failures != 0 {
		t.Errorf("SEC-28 FAILED: Expected 0 failures in healthy environment, got %d", report.Failures)
	}
}

// TestSEC28_DoctorDiagnosesCorruptedPolicy verifies that doctor detects broken/corrupted
// declarative configuration files, fails closed, and marks the system unhealthy (SEC-28).
func TestSEC28_DoctorDiagnosesCorruptedPolicy(t *testing.T) {
	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	// Write malformed YAML into airlock.yaml
	cfgPath := filepath.Join(workspace, "airlock.yaml")
	_ = os.WriteFile(cfgPath, []byte("version: {invalid yaml structure :::"), 0644)

	opts := doctor.Options{
		WorkspaceRoot: workspace,
		HomeDir:       tempDir,
	}

	report, err := doctor.RunChecks(context.Background(), opts)
	if err != nil {
		t.Fatalf("SEC-28 FAILED: RunChecks failed: %v", err)
	}

	if report.Healthy {
		t.Fatalf("SEC-28 FAILED: Expected report to be Unhealthy due to corrupted policy file")
	}

	var foundConfigFail bool
	for _, res := range report.Results {
		if res.ID == "config-airlock-yaml" && res.Status == doctor.StatusFail {
			foundConfigFail = true
			if !strings.Contains(res.Details, "Failed to parse") {
				t.Errorf("SEC-28 FAILED: Expected parse error in details, got: %s", res.Details)
			}
			if res.Recommendation == "" {
				t.Errorf("SEC-28 FAILED: Expected recommendation for fixing corrupted config")
			}
		}
	}

	if !foundConfigFail {
		t.Errorf("SEC-28 FAILED: config-airlock-yaml check was not marked FAIL")
	}
}

// TestSEC28_DoctorDiagnosesSecurityGuardrailViolations verifies that declarative config
// attempting to bypass security invariants generates warnings with recommendations (SEC-28).
func TestSEC28_DoctorDiagnosesSecurityGuardrailViolations(t *testing.T) {
	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	// Write policy with forbidden paths
	cfgPath := filepath.Join(workspace, "airlock.yaml")
	_ = os.WriteFile(cfgPath, []byte(`version: "1"
mode: "strict"
filesystem:
  allow_read:
    - "~/.ssh"
    - "/var/run/docker.sock"
env:
  allow:
    - "DYLD_INSERT_LIBRARIES"
`), 0644)

	opts := doctor.Options{
		WorkspaceRoot: workspace,
		HomeDir:       tempDir,
	}

	report, err := doctor.RunChecks(context.Background(), opts)
	if err != nil {
		t.Fatalf("SEC-28 FAILED: RunChecks failed: %v", err)
	}

	var foundGuardrailWarn bool
	for _, res := range report.Results {
		if res.ID == "config-airlock-yaml" && res.Status == doctor.StatusWarn {
			foundGuardrailWarn = true
			if !strings.Contains(res.Details, "guardrail notices") {
				t.Errorf("SEC-28 FAILED: Expected guardrail notice in details: %s", res.Details)
			}
		}
	}

	if !foundGuardrailWarn {
		t.Errorf("SEC-28 FAILED: Expected config-airlock-yaml to warn on guardrail violation")
	}
}

// TestSEC28_DoctorDiagnosesStoragePermissionFailure verifies that storage permission
// denials are identified and reported as failures (SEC-28).
func TestSEC28_DoctorDiagnosesStoragePermissionFailure(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows directories do not support POSIX read-only mode bits")
	}

	tempDir := t.TempDir()
	readOnlyHome := filepath.Join(tempDir, "ro_home")
	_ = os.Mkdir(readOnlyHome, 0555)
	defer func() { _ = os.Chmod(readOnlyHome, 0755) }()

	opts := doctor.Options{
		HomeDir:       readOnlyHome,
		WorkspaceRoot: tempDir,
		ScratchBase:   tempDir,
	}

	report, err := doctor.RunChecks(context.Background(), opts)
	if err != nil {
		t.Fatalf("SEC-28 FAILED: RunChecks failed: %v", err)
	}

	var foundStorageFail bool
	for _, res := range report.Results {
		if res.ID == "storage-airlock-dir" && res.Status == doctor.StatusFail {
			foundStorageFail = true
			if res.Recommendation == "" {
				t.Errorf("SEC-28 FAILED: Missing recommendation for storage permission fix")
			}
		}
	}

	if !foundStorageFail {
		t.Errorf("SEC-28 FAILED: Expected storage-airlock-dir check to fail on unwritable home")
	}

	if report.Healthy {
		t.Errorf("SEC-28 FAILED: Expected system to be marked Unhealthy on storage failure")
	}
}

// TestSEC28_DoctorDiagnosesUnsupportedPlatform verifies that doctor diagnoses unsupported
// host operating systems as FAIL (SEC-28).
func TestSEC28_DoctorDiagnosesUnsupportedPlatform(t *testing.T) {
	tempDir := t.TempDir()
	opts := doctor.Options{
		WorkspaceRoot: tempDir,
		HomeDir:       tempDir,
		GOOS:          "solaris",
		GOARCH:        "amd64",
	}

	report, err := doctor.RunChecks(context.Background(), opts)
	if err != nil {
		t.Fatalf("SEC-28 FAILED: RunChecks failed: %v", err)
	}

	if report.Healthy {
		t.Errorf("SEC-28 FAILED: Expected solaris platform to be marked Unhealthy")
	}

	var foundPlatformFail bool
	for _, res := range report.Results {
		if res.ID == "sandbox-platform-support" && res.Status == doctor.StatusFail {
			foundPlatformFail = true
		}
	}

	if !foundPlatformFail {
		t.Errorf("SEC-28 FAILED: Expected sandbox-platform-support check to fail for solaris")
	}
}

// TestSEC28_DoctorJSONExportAndTerminalFormatting verifies that doctor reports can be
// accurately serialized into JSON and rendered for terminal output (SEC-28).
func TestSEC28_DoctorJSONExportAndTerminalFormatting(t *testing.T) {
	tempDir := t.TempDir()
	report, err := doctor.RunAllChecks(context.Background(), tempDir)
	if err != nil {
		t.Fatalf("SEC-28 FAILED: RunAllChecks failed: %v", err)
	}

	// 1. JSON Export
	jsonData, err := report.ToJSON()
	if err != nil {
		t.Fatalf("SEC-28 FAILED: ToJSON failed: %v", err)
	}

	var parsed doctor.Report
	if err := json.Unmarshal(jsonData, &parsed); err != nil {
		t.Fatalf("SEC-28 FAILED: Failed to unmarshal doctor JSON output: %v", err)
	}

	if len(parsed.Results) != len(report.Results) {
		t.Errorf("SEC-28 FAILED: Result count mismatch after JSON roundtrip: %d vs %d", len(parsed.Results), len(report.Results))
	}

	// 2. Formatted terminal output
	terminalOutput := report.FormatTerminal(false)
	if !strings.Contains(terminalOutput, "Airlock Doctor — System Diagnostics & Health Report") {
		t.Errorf("SEC-28 FAILED: Terminal output missing title banner")
	}
	if !strings.Contains(terminalOutput, "Summary:") {
		t.Errorf("SEC-28 FAILED: Terminal output missing Summary section")
	}

	coloredOutput := report.FormatTerminal(true)
	if len(coloredOutput) <= len(terminalOutput) && runtime.GOOS != "windows" {
		t.Errorf("SEC-28 FAILED: Colored terminal output did not include ANSI escapes")
	}
}
