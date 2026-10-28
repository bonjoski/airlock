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

func TestFindWorkspaceRoot(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Node monorepo
	nodeRoot := filepath.Join(tempDir, "node-repo")
	_ = os.MkdirAll(filepath.Join(nodeRoot, "packages", "core", "src"), 0755)
	_ = os.WriteFile(filepath.Join(nodeRoot, "package.json"), []byte("{}"), 0644)
	if found := FindWorkspaceRoot(filepath.Join(nodeRoot, "packages", "core", "src")); found != nodeRoot {
		t.Errorf("Expected node root %s, got %s", nodeRoot, found)
	}

	// 2. Java Maven repo
	javaRoot := filepath.Join(tempDir, "java-repo")
	_ = os.MkdirAll(filepath.Join(javaRoot, "src", "main", "java"), 0755)
	_ = os.WriteFile(filepath.Join(javaRoot, "pom.xml"), []byte("<project></project>"), 0644)
	if found := FindWorkspaceRoot(filepath.Join(javaRoot, "src", "main", "java")); found != javaRoot {
		t.Errorf("Expected java root %s, got %s", javaRoot, found)
	}

	// 3. .NET solution repo
	dotnetRoot := filepath.Join(tempDir, "dotnet-repo")
	_ = os.MkdirAll(filepath.Join(dotnetRoot, "Services", "Api"), 0755)
	_ = os.WriteFile(filepath.Join(dotnetRoot, "Solution.sln"), []byte(""), 0644)
	if found := FindWorkspaceRoot(filepath.Join(dotnetRoot, "Services", "Api")); found != dotnetRoot {
		t.Errorf("Expected dotnet root %s, got %s", dotnetRoot, found)
	}

	// 4. Ruby repo
	rubyRoot := filepath.Join(tempDir, "ruby-repo")
	_ = os.MkdirAll(filepath.Join(rubyRoot, "app", "models"), 0755)
	_ = os.WriteFile(filepath.Join(rubyRoot, "Gemfile"), []byte("source 'https://rubygems.org'"), 0644)
	if found := FindWorkspaceRoot(filepath.Join(rubyRoot, "app", "models")); found != rubyRoot {
		t.Errorf("Expected ruby root %s, got %s", rubyRoot, found)
	}

	// 5. Swift package repo
	swiftRoot := filepath.Join(tempDir, "swift-repo")
	_ = os.MkdirAll(filepath.Join(swiftRoot, "Sources", "MyLib"), 0755)
	_ = os.WriteFile(filepath.Join(swiftRoot, "Package.swift"), []byte("// swift-tools-version: 5.9"), 0644)
	if found := FindWorkspaceRoot(filepath.Join(swiftRoot, "Sources", "MyLib")); found != swiftRoot {
		t.Errorf("Expected swift root %s, got %s", swiftRoot, found)
	}
}

func TestMacOSEngine_Execute(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var stdout, stderr bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		Airgap:         true,
		NonInteractive: true,
		Stdout:         &stdout,
		Stderr:         &stderr,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/echo", "airlock_go_engine_test"})
	if err != nil {
		t.Fatalf("Engine.Execute failed: %v (stderr: %s)", err, stderr.String())
	}
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "airlock_go_engine_test") {
		t.Errorf("Expected output not found in stdout: %s", stdout.String())
	}
}

func TestMacOSEngine_ExitCodePropagation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine exit code test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var stdout, stderr bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		Airgap:         true,
		NonInteractive: true,
		Stdout:         &stdout,
		Stderr:         &stderr,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/sh", "-c", "exit 42"})
	if err != nil {
		t.Fatalf("Engine.Execute failed: %v", err)
	}
	if exitCode != 42 {
		t.Errorf("Expected exit code 42, got %d", exitCode)
	}
}

func TestMacOSEngine_NestedBypass(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine nested bypass test on non-darwin platform")
	}

	_ = os.Setenv("__AIRLOCK_ACTIVE", "1")
	defer os.Unsetenv("__AIRLOCK_ACTIVE")

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.Mkdir(workspace, 0755)

	var stdout bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		NonInteractive: true,
		Stdout:         &stdout,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/echo", "nested_bypass_ok"})
	if err != nil {
		t.Fatalf("Nested execution failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}
	if !strings.Contains(stdout.String(), "nested_bypass_ok") {
		t.Errorf("Expected output not found: %s", stdout.String())
	}
}

func TestMacOSEngine_PreservesWorkingDir(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping MacOSEngine test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	subDir := filepath.Join(workspace, "packages", "pkg-a")
	_ = os.MkdirAll(subDir, 0755)

	var stdout, stderr bytes.Buffer
	opts := Options{
		WorkspaceRoot:  workspace,
		WorkingDir:     subDir,
		Airgap:         true,
		NonInteractive: true,
		Stdout:         &stdout,
		Stderr:         &stderr,
	}

	engine, err := NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	ctx := context.Background()
	exitCode, err := engine.Execute(ctx, []string{"/bin/pwd"})
	if err != nil {
		t.Fatalf("Engine.Execute failed: %v", err)
	}
	if exitCode != 0 {
		t.Errorf("Expected exit code 0, got %d", exitCode)
	}

	resolvedSubDir, _ := filepath.EvalSymlinks(subDir)
	outputDir := strings.TrimSpace(stdout.String())
	if outputDir != resolvedSubDir {
		t.Errorf("Expected cwd %s, got %s", resolvedSubDir, outputDir)
	}
}
