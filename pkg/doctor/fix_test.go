package doctor

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestAutoFix_EndToEndRemediation(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	wsDir := filepath.Join(tempDir, "workspace")
	homeDir := filepath.Join(tempDir, "home")
	shimDir := filepath.Join(homeDir, ".airlock", "bin")
	realBinDir := filepath.Join(tempDir, "realbin")

	if err := os.MkdirAll(wsDir, 0755); err != nil {
		t.Fatalf("failed to create wsDir: %v", err)
	}
	if err := os.MkdirAll(shimDir, 0755); err != nil {
		t.Fatalf("failed to create shimDir: %v", err)
	}
	if err := os.MkdirAll(realBinDir, 0755); err != nil {
		t.Fatalf("failed to create realBinDir: %v", err)
	}

	// 1. Create a go.mod in workspace so project profile is detected as "go"
	if err := os.WriteFile(filepath.Join(wsDir, "go.mod"), []byte("module example.com/test\ngo 1.22\n"), 0644); err != nil {
		t.Fatalf("failed to create go.mod: %v", err)
	}

	// 2. Plant shadowed airlock binary in shimDir
	airlockBinName := "airlock"
	if runtime.GOOS == "windows" {
		airlockBinName = "airlock.exe"
	}
	shadowedPath := filepath.Join(shimDir, airlockBinName)
	if err := os.WriteFile(shadowedPath, []byte("#!/bin/sh\necho shadowed\n"), 0755); err != nil {
		t.Fatalf("failed to create shadowed binary: %v", err)
	}

	// 3. Set up shims:
	// "npm" has a real host binary in realBinDir -> should be KEPT.
	// "bun" has NO real host binary -> orphan shim -> should be UNINSTALLED.
	realNpmPath := filepath.Join(realBinDir, "npm")
	if runtime.GOOS == "windows" {
		realNpmPath = filepath.Join(realBinDir, "npm.cmd")
	}
	if err := os.WriteFile(realNpmPath, []byte("#!/bin/sh\necho real npm\n"), 0755); err != nil {
		t.Fatalf("failed to create real npm: %v", err)
	}

	npmShimPath := filepath.Join(shimDir, "npm")
	if err := os.WriteFile(npmShimPath, []byte("#!/bin/sh\nexec airlock npm \"$@\"\n"), 0755); err != nil {
		t.Fatalf("failed to create npm shim: %v", err)
	}
	bunShimPath := filepath.Join(shimDir, "bun")
	if err := os.WriteFile(bunShimPath, []byte("#!/bin/sh\nexec airlock bun \"$@\"\n"), 0755); err != nil {
		t.Fatalf("failed to create bun shim: %v", err)
	}

	pathEnv := realBinDir

	opts := Options{
		WorkspaceRoot: wsDir,
		HomeDir:       homeDir,
		ShimDir:       shimDir,
		PathEnv:       pathEnv,
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
	}

	// Run AutoFix
	fixReport, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("AutoFix returned error: %v", err)
	}

	if fixReport == nil {
		t.Fatal("Expected non-nil FixReport")
	}

	if fixReport.Repaired != 4 {
		t.Errorf("Expected 4 repaired actions, got %d (skipped=%d, failed=%d)",
			fixReport.Repaired, fixReport.Skipped, fixReport.Failed)
		for _, a := range fixReport.Actions {
			t.Logf("Action: [%s] %s: %s", a.Status, a.ID, a.Details)
		}
	}

	if fixReport.Failed != 0 {
		t.Errorf("Expected 0 failures, got %d", fixReport.Failed)
	}

	// Assertions on filesystem state:
	// a. Shadowed binary removed
	if _, err := os.Lstat(shadowedPath); !os.IsNotExist(err) {
		t.Errorf("Shadowed binary %s still exists after AutoFix", shadowedPath)
	}

	// b. Orphan shim uninstalled, valid shim preserved
	if _, err := os.Lstat(bunShimPath); !os.IsNotExist(err) {
		t.Errorf("Orphan shim %s was not uninstalled", bunShimPath)
	}
	if _, err := os.Lstat(npmShimPath); os.IsNotExist(err) {
		t.Errorf("Legitimate shim %s was unexpectedly removed", npmShimPath)
	}

	// c. Baseline airlock.yaml created with go profile
	generatedPolicy := filepath.Join(wsDir, "airlock.yaml")
	policyData, err := os.ReadFile(generatedPolicy)
	if err != nil {
		t.Fatalf("Failed to read generated policy %s: %v", generatedPolicy, err)
	}
	if !strings.Contains(string(policyData), "Go Workspace") || !strings.Contains(string(policyData), "proxy.golang.org") {
		t.Errorf("Generated policy missing expected Go profile content: %s", string(policyData))
	}

	// d. Scratch & cache directories provisioned with 0700
	scratchDir := filepath.Join(homeDir, ".airlock", "scratch")
	cacheDir := filepath.Join(homeDir, ".airlock", "cache")

	checkDirPerms := func(dir string) {
		fi, err := os.Lstat(dir)
		if err != nil {
			t.Fatalf("Failed to stat dir %s: %v", dir, err)
		}
		if !fi.IsDir() {
			t.Fatalf("%s is not a directory", dir)
		}
		if runtime.GOOS != "windows" {
			if fi.Mode().Perm() != 0700 {
				t.Errorf("Dir %s has perm %04o, expected 0700", dir, fi.Mode().Perm())
			}
		}
	}
	checkDirPerms(scratchDir)
	checkDirPerms(cacheDir)

	// Re-run diagnostic checks: all 4 issues should now PASS
	diagReport, err := RunChecks(ctx, opts)
	if err != nil {
		t.Fatalf("RunChecks failed after AutoFix: %v", err)
	}

	for _, res := range diagReport.Results {
		switch res.ID {
		case "shims-shadowing-airlock":
			t.Errorf("shims-shadowing-airlock check should not exist or be PASS, got %+v", res)
		case "config-airlock-yaml":
			if res.Status != StatusPass {
				t.Errorf("Expected config-airlock-yaml to PASS after fix, got %s: %s", res.Status, res.Details)
			}
		case "storage-scratch-dirs":
			if res.Status != StatusPass {
				t.Errorf("Expected storage-scratch-dirs to PASS after fix, got %s: %s", res.Status, res.Details)
			}
		}
	}
}

func TestAutoFix_Idempotent(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	wsDir := filepath.Join(tempDir, "workspace")
	homeDir := filepath.Join(tempDir, "home")
	shimDir := filepath.Join(homeDir, ".airlock", "bin")
	_ = os.MkdirAll(wsDir, 0755)
	_ = os.MkdirAll(shimDir, 0755)

	opts := Options{
		WorkspaceRoot: wsDir,
		HomeDir:       homeDir,
		ShimDir:       shimDir,
		PathEnv:       os.Getenv("PATH"),
		GOOS:          runtime.GOOS,
		GOARCH:        runtime.GOARCH,
	}

	// First pass: creates policy and scratch dirs
	firstReport, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("First AutoFix failed: %v", err)
	}
	if firstReport.Repaired == 0 {
		t.Fatal("First pass should have repaired baseline items")
	}

	// Record file mod times
	policyPath := filepath.Join(wsDir, "airlock.yaml")
	fi1, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("Failed to stat generated policy: %v", err)
	}

	// Second pass: idempotent execution
	secondReport, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("Second AutoFix failed: %v", err)
	}

	if secondReport.Repaired != 0 {
		t.Errorf("Expected 0 repairs on second pass, got %d", secondReport.Repaired)
		for _, a := range secondReport.Actions {
			t.Logf("Second pass action: [%s] %s: %s", a.Status, a.ID, a.Details)
		}
	}
	if secondReport.Failed != 0 {
		t.Errorf("Expected 0 failures on second pass, got %d", secondReport.Failed)
	}
	if secondReport.Skipped != 4 {
		t.Errorf("Expected 4 skipped actions on second pass, got %d", secondReport.Skipped)
	}

	// Ensure policy file was untouched
	fi2, err := os.Stat(policyPath)
	if err != nil {
		t.Fatalf("Failed to stat policy after second run: %v", err)
	}
	if fi1.ModTime() != fi2.ModTime() {
		t.Errorf("Policy file was modified on second pass (mtime changed)")
	}
}

func TestAutoFix_NonDestructive_ExistingCustomConfig(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	wsDir := filepath.Join(tempDir, "workspace")
	homeDir := filepath.Join(tempDir, "home")
	shimDir := filepath.Join(homeDir, ".airlock", "bin")
	_ = os.MkdirAll(wsDir, 0755)
	_ = os.MkdirAll(shimDir, 0755)

	customContent := "# Custom Team Policy\nversion: \"1\"\nmode: permissive\n"
	customPolicyPath := filepath.Join(wsDir, "airlock.yaml")
	if err := os.WriteFile(customPolicyPath, []byte(customContent), 0644); err != nil {
		t.Fatalf("failed to write custom policy: %v", err)
	}

	opts := Options{
		WorkspaceRoot: wsDir,
		HomeDir:       homeDir,
		ShimDir:       shimDir,
	}

	report, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("AutoFix failed: %v", err)
	}

	// Verify declarative config action was SKIPPED
	var configAction *FixAction
	for _, a := range report.Actions {
		if a.ID == "config-airlock-yaml" {
			configAction = &a
			break
		}
	}
	if configAction == nil || configAction.Status != FixSkipped {
		t.Errorf("Expected config-airlock-yaml to be SKIPPED, got %+v", configAction)
	}

	// Verify content was not modified
	data, _ := os.ReadFile(customPolicyPath)
	if string(data) != customContent {
		t.Errorf("Custom policy was overwritten: %s", string(data))
	}
}

func TestAutoFix_Adversarial_SymlinkSafety_ShadowedBinary(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink safety tests skipped on Windows (unprivileged symlinks disabled by default)")
	}

	ctx := context.Background()
	tempDir := t.TempDir()

	homeDir := filepath.Join(tempDir, "home")
	shimDir := filepath.Join(homeDir, ".airlock", "bin")
	_ = os.MkdirAll(shimDir, 0755)

	// Attacker puts a sensitive file outside shimDir
	sensitiveFile := filepath.Join(tempDir, "sensitive_system_file.txt")
	secretContent := "CRITICAL_SECRET_DATA_DO_NOT_DELETE"
	if err := os.WriteFile(sensitiveFile, []byte(secretContent), 0600); err != nil {
		t.Fatalf("failed to write sensitive file: %v", err)
	}

	// Attacker creates a symlink ~/.airlock/bin/airlock -> sensitiveFile
	symlinkPath := filepath.Join(shimDir, "airlock")
	if err := os.Symlink(sensitiveFile, symlinkPath); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       homeDir,
		ShimDir:       shimDir,
	}

	report, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("AutoFix failed: %v", err)
	}

	// The action should repair the shadowed symlink
	var action *FixAction
	for _, a := range report.Actions {
		if a.ID == "shims-shadowing-airlock" {
			action = &a
			break
		}
	}
	if action == nil || action.Status != FixRepaired {
		t.Fatalf("Expected shims-shadowing-airlock to be REPAIRED, got %+v", action)
	}

	// 1. The symlink in shim directory must be deleted
	if _, err := os.Lstat(symlinkPath); !os.IsNotExist(err) {
		t.Errorf("Symlink at %s was not removed", symlinkPath)
	}

	// 2. The target sensitive file MUST NOT be deleted or altered
	targetData, err := os.ReadFile(sensitiveFile)
	if err != nil {
		t.Fatalf("Sensitive target file was deleted or corrupted! err: %v", err)
	}
	if string(targetData) != secretContent {
		t.Errorf("Sensitive target file content modified: %q", string(targetData))
	}
}

func TestAutoFix_Adversarial_SymlinkSafety_ScratchDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink safety tests skipped on Windows")
	}

	ctx := context.Background()
	tempDir := t.TempDir()

	homeDir := filepath.Join(tempDir, "home")
	airlockBase := filepath.Join(homeDir, ".airlock")
	_ = os.MkdirAll(airlockBase, 0755)

	// Attacker creates sensitive target directory with 0777 perms and files
	sensitiveDir := filepath.Join(tempDir, "sensitive_shared_dir")
	if err := os.MkdirAll(sensitiveDir, 0755); err != nil {
		t.Fatalf("failed to create sensitiveDir: %v", err)
	}
	if err := os.Chmod(sensitiveDir, 0777); err != nil {
		t.Fatalf("failed to chmod sensitiveDir: %v", err)
	}
	secretFile := filepath.Join(sensitiveDir, "data.txt")
	_ = os.WriteFile(secretFile, []byte("valuable-data"), 0644)

	// Attacker creates symlink ~/.airlock/scratch -> sensitiveDir
	scratchSymlink := filepath.Join(airlockBase, "scratch")
	if err := os.Symlink(sensitiveDir, scratchSymlink); err != nil {
		t.Fatalf("failed to create scratch symlink: %v", err)
	}

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       homeDir,
	}

	report, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("AutoFix failed: %v", err)
	}

	var storageAction *FixAction
	for _, a := range report.Actions {
		if a.ID == "storage-scratch-dirs" {
			storageAction = &a
			break
		}
	}
	if storageAction == nil || storageAction.Status != FixRepaired {
		t.Fatalf("Expected storage-scratch-dirs to be REPAIRED, got %+v", storageAction)
	}

	// 1. Sensitive dir must NOT be altered or chmod'd
	sensFi, err := os.Stat(sensitiveDir)
	if err != nil {
		t.Fatalf("Sensitive dir was removed! err: %v", err)
	}
	if sensFi.Mode().Perm() != 0777 {
		t.Errorf("Sensitive dir permissions were hijacked! Mode: %04o", sensFi.Mode().Perm())
	}
	if _, err := os.Stat(secretFile); err != nil {
		t.Errorf("File inside sensitive dir was deleted! err: %v", err)
	}

	// 2. ~/.airlock/scratch must now be a real directory with 0700 (not a symlink)
	fi, err := os.Lstat(scratchSymlink)
	if err != nil {
		t.Fatalf("Failed to lstat scratch dir: %v", err)
	}
	if fi.Mode()&os.ModeSymlink != 0 {
		t.Errorf("Scratch dir is still a symlink!")
	}
	if !fi.IsDir() {
		t.Errorf("Scratch dir is not a directory")
	}
	if fi.Mode().Perm() != 0700 {
		t.Errorf("Scratch dir permissions expected 0700, got %04o", fi.Mode().Perm())
	}
}

func TestAutoFix_Adversarial_SymlinkSafety_PolicyFile(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Symlink safety tests skipped on Windows")
	}

	ctx := context.Background()
	tempDir := t.TempDir()

	wsDir := filepath.Join(tempDir, "workspace")
	homeDir := filepath.Join(tempDir, "home")
	_ = os.MkdirAll(wsDir, 0755)
	_ = os.MkdirAll(homeDir, 0755)

	// Attacker creates sensitive target file
	sensitiveTarget := filepath.Join(tempDir, "etc_passwd_simulation")
	sensitiveContent := "root:x:0:0:root:/root:/bin/bash"
	_ = os.WriteFile(sensitiveTarget, []byte(sensitiveContent), 0644)

	// Symlink airlock.yaml -> sensitiveTarget
	symlinkPolicy := filepath.Join(wsDir, "airlock.yaml")
	if err := os.Symlink(sensitiveTarget, symlinkPolicy); err != nil {
		t.Fatalf("failed to create symlink: %v", err)
	}

	opts := Options{
		WorkspaceRoot: wsDir,
		HomeDir:       homeDir,
	}

	report, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("AutoFix failed: %v", err)
	}

	// Declarative config check should SKIP because policy already exists (symlink)
	var configAction *FixAction
	for _, a := range report.Actions {
		if a.ID == "config-airlock-yaml" {
			configAction = &a
			break
		}
	}
	if configAction == nil || configAction.Status != FixSkipped {
		t.Errorf("Expected config-airlock-yaml to be SKIPPED, got %+v", configAction)
	}

	// Target file must be unmodified
	data, _ := os.ReadFile(sensitiveTarget)
	if string(data) != sensitiveContent {
		t.Errorf("Sensitive target file was modified by AutoFix! Got: %s", string(data))
	}
}

func TestAutoFix_Adversarial_DirectoryAsAirlockBinary(t *testing.T) {
	ctx := context.Background()
	tempDir := t.TempDir()

	homeDir := filepath.Join(tempDir, "home")
	shimDir := filepath.Join(homeDir, ".airlock", "bin")
	_ = os.MkdirAll(shimDir, 0755)

	// Attacker creates a DIRECTORY named "airlock" inside shimDir
	dirAsBinary := filepath.Join(shimDir, "airlock")
	if err := os.Mkdir(dirAsBinary, 0755); err != nil {
		t.Fatalf("failed to create dir: %v", err)
	}

	opts := Options{
		WorkspaceRoot: tempDir,
		HomeDir:       homeDir,
		ShimDir:       shimDir,
	}

	report, err := AutoFix(ctx, opts)
	if err != nil {
		t.Fatalf("AutoFix returned unexpected top-level error: %v", err)
	}

	var action *FixAction
	for _, a := range report.Actions {
		if a.ID == "shims-shadowing-airlock" {
			action = &a
			break
		}
	}
	if action == nil || action.Status != FixFailed {
		t.Fatalf("Expected shims-shadowing-airlock to FAIL when target is a directory, got %+v", action)
	}
	if !strings.Contains(action.Details, "is a directory") {
		t.Errorf("Expected error details to mention directory, got: %s", action.Details)
	}

	// The directory must not have been removed
	if fi, err := os.Stat(dirAsBinary); err != nil || !fi.IsDir() {
		t.Errorf("Directory %s was unexpectedly removed", dirAsBinary)
	}
}

func TestAutoFix_FormatTerminal(t *testing.T) {
	report := &FixReport{
		Repaired: 2,
		Skipped:  1,
		Failed:   1,
		Actions: []FixAction{
			{
				ID:      "shims-shadowing-airlock",
				Status:  FixRepaired,
				Details: "Removed shadowed binary",
			},
			{
				ID:      "config-airlock-yaml",
				Status:  FixSkipped,
				Details: "Policy already present",
			},
			{
				ID:      "storage-scratch-dirs",
				Status:  FixFailed,
				Details: "Permission denied",
			},
		},
	}

	// Plain text
	plain := report.FormatTerminal(false)
	if !strings.Contains(plain, "Airlock Doctor — Auto-Remediation Summary") {
		t.Errorf("Missing summary banner: %s", plain)
	}
	if !strings.Contains(plain, "REPAIRED") || !strings.Contains(plain, "SKIPPED") || !strings.Contains(plain, "FAILED") {
		t.Errorf("Missing status tags: %s", plain)
	}
	if !strings.Contains(plain, "shims-shadowing-airlock") {
		t.Errorf("Missing action ID: %s", plain)
	}
	if !strings.Contains(plain, "2 repaired, 1 skipped, 1 failed") {
		t.Errorf("Missing summary totals: %s", plain)
	}

	// Colored text
	colored := report.FormatTerminal(true)
	if !strings.Contains(colored, "\033[32m") { // green for REPAIRED
		t.Errorf("Colored output missing green ANSI code")
	}
	if !strings.Contains(colored, "\033[33m") { // yellow for SKIPPED
		t.Errorf("Colored output missing yellow ANSI code")
	}
	if !strings.Contains(colored, "\033[31m") { // red for FAILED
		t.Errorf("Colored output missing red ANSI code")
	}
}
