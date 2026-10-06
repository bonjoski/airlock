// Package shim manages transparent toolchain shims for package managers
// with recursion prevention and host binary auto-discovery (Target 2 / V-14).
package shim

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
)

// SupportedTools lists package managers and build tools supported by Airlock shims.
var SupportedTools = []string{
	"npm", "npx", "pnpm", "yarn", "pip", "pip3", "cargo", "uv", "bun",
}

// ShimStatus describes the installation state of a particular toolchain shim.
type ShimStatus struct {
	Tool             string `json:"tool"`
	Installed        bool   `json:"installed"`
	ShimPath         string `json:"shim_path"`
	TargetHostBinary string `json:"target_host_binary,omitempty"`
}

// Manager defines the lifecycle operations for transparent toolchain shims.
type Manager interface {
	Install(targetDir string) ([]string, error)
	Uninstall(targetDir string) error
	List(targetDir string) ([]ShimStatus, error)
	DefaultShimDir() (string, error)
}

// DefaultManager implements Manager.
type DefaultManager struct{}

// NewManager creates a new toolchain shim manager.
func NewManager() *DefaultManager {
	return &DefaultManager{}
}

// DefaultShimDir returns ~/.airlock/bin.
func (m *DefaultManager) DefaultShimDir() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("shim: failed to determine user home: %w", err)
	}
	return filepath.Join(home, ".airlock", "bin"), nil
}

// Install generates transparent shell shims in targetDir for all supported tools.
func (m *DefaultManager) Install(targetDir string) ([]string, error) {
	if targetDir == "" {
		def, err := m.DefaultShimDir()
		if err != nil {
			return nil, err
		}
		targetDir = def
	}

	if err := os.MkdirAll(targetDir, 0755); err != nil {
		return nil, fmt.Errorf("shim: failed to create directory %s: %w", targetDir, err)
	}

	var installed []string
	for _, tool := range SupportedTools {
		shimPath := filepath.Join(targetDir, tool)
		content := generateShimScript(tool)
		if err := os.WriteFile(shimPath, []byte(content), 0755); err != nil {
			return installed, fmt.Errorf("shim: failed to write %s: %w", shimPath, err)
		}
		installed = append(installed, shimPath)

		// On Windows, additionally generate .cmd batch wrapper
		if runtime.GOOS == "windows" {
			cmdPath := filepath.Join(targetDir, tool+".cmd")
			cmdContent := generateWindowsCmdScript(tool)
			if err := os.WriteFile(cmdPath, []byte(cmdContent), 0755); err != nil {
				return installed, fmt.Errorf("shim: failed to write %s: %w", cmdPath, err)
			}
			installed = append(installed, cmdPath)
		}
	}

	return installed, nil
}

// Uninstall removes all airlock shims from targetDir.
func (m *DefaultManager) Uninstall(targetDir string) error {
	if targetDir == "" {
		def, err := m.DefaultShimDir()
		if err != nil {
			return err
		}
		targetDir = def
	}

	for _, tool := range SupportedTools {
		shimPath := filepath.Join(targetDir, tool)
		if err := os.Remove(shimPath); err != nil && !os.IsNotExist(err) {
			return fmt.Errorf("shim: failed to remove %s: %w", shimPath, err)
		}

		cmdPath := filepath.Join(targetDir, tool+".cmd")
		_ = os.Remove(cmdPath)
	}

	return nil
}

// List inspects targetDir and returns the status of each supported tool.
func (m *DefaultManager) List(targetDir string) ([]ShimStatus, error) {
	if targetDir == "" {
		def, err := m.DefaultShimDir()
		if err != nil {
			return nil, err
		}
		targetDir = def
	}

	var results []ShimStatus
	for _, tool := range SupportedTools {
		shimPath := filepath.Join(targetDir, tool)
		status := ShimStatus{
			Tool:     tool,
			ShimPath: shimPath,
		}

		if info, err := os.Stat(shimPath); err == nil && !info.IsDir() {
			status.Installed = true
		} else if runtime.GOOS == "windows" {
			if info, err := os.Stat(filepath.Join(targetDir, tool+".cmd")); err == nil && !info.IsDir() {
				status.Installed = true
			}
		}

		// Locate host executable outside of shim directory
		if hostBin := findHostBinary(tool, targetDir); hostBin != "" {
			status.TargetHostBinary = hostBin
		}

		results = append(results, status)
	}

	return results, nil
}

func findHostBinary(tool string, shimDir string) string {
	pathVar := os.Getenv("PATH")
	entries := filepath.SplitList(pathVar)
	cleanShimDir := filepath.Clean(shimDir)

	for _, entry := range entries {
		cleanEntry := filepath.Clean(entry)
		if cleanEntry == cleanShimDir {
			continue
		}
		candidates := []string{filepath.Join(cleanEntry, tool)}
		if runtime.GOOS == "windows" {
			candidates = append(candidates,
				filepath.Join(cleanEntry, tool+".cmd"),
				filepath.Join(cleanEntry, tool+".exe"),
				filepath.Join(cleanEntry, tool+".bat"),
			)
		}
		for _, candidate := range candidates {
			if info, err := os.Stat(candidate); err == nil && !info.IsDir() {
				if IsExecutable(info) {
					return candidate
				}
			}
		}
	}

	// Fallback to exec.LookPath
	if p, err := exec.LookPath(tool); err == nil {
		if filepath.Clean(filepath.Dir(p)) != cleanShimDir {
			return p
		}
	}

	return ""
}

func generateShimScript(tool string) string {
	var sb strings.Builder
	sb.WriteString("#!/bin/sh\n")
	sb.WriteString(fmt.Sprintf("# Airlock Transparent Toolchain Shim for %s\n", tool))
	sb.WriteString("# Copyright 2026 Ben Skolmoski - MIT License\n\n")
	sb.WriteString(fmt.Sprintf("TOOL=\"%s\"\n\n", tool))
	sb.WriteString("# 1. Nested Execution Sentinel Bypass (V-14 / Phase 1)\n")
	sb.WriteString("# When running inside an active Airlock boundary, find and exec the real host binary\n")
	sb.WriteString("# outside of this shim directory to prevent recursion and fork bombs.\n")
	sb.WriteString("if [ \"$__AIRLOCK_ACTIVE\" = \"1\" ]; then\n")
	sb.WriteString("    CURRENT_DIR=$(CDPATH= cd -- \"$(dirname -- \"$0\")\" && pwd)\n")
	sb.WriteString("    IFS=':'\n")
	sb.WriteString("    for p in $PATH; do\n")
	sb.WriteString("        if [ -n \"$p\" ] && [ \"$p\" != \"$CURRENT_DIR\" ] && [ -x \"$p/$TOOL\" ]; then\n")
	sb.WriteString("            exec \"$p/$TOOL\" \"$@\"\n")
	sb.WriteString("        fi\n")
	sb.WriteString("    done\n")
	sb.WriteString("    unset IFS\n")
	sb.WriteString("    echo \"airlock shim: unable to locate host $TOOL outside of $CURRENT_DIR\" >&2\n")
	sb.WriteString("    exit 127\n")
	sb.WriteString("fi\n\n")
	sb.WriteString("# 2. Forward execution to airlock supervisor\n")
	sb.WriteString("exec airlock \"$TOOL\" \"$@\"\n")
	return sb.String()
}

// IsExecutable checks whether a file is executable on the current platform.
// On Windows, executability is determined by file extension and PATHEXT.
// On POSIX systems, it verifies that at least one executable bit (0111) is set.
func IsExecutable(info os.FileInfo) bool {
	if runtime.GOOS == "windows" {
		return true
	}
	return info.Mode()&0111 != 0
}

const windowsCmdTemplate = `@echo off
rem Airlock Transparent Toolchain Shim for {{TOOL}}
rem Copyright 2026 Ben Skolmoski - MIT License

setlocal
if "%__AIRLOCK_ACTIVE%"=="1" (
    set "CURRENT_DIR=%~dp0"
    for %%F in ({{TOOL}}.cmd {{TOOL}}.exe {{TOOL}}.bat {{TOOL}}) do (
        for /f "delims=" %%I in ('where %%F 2^>nul') do (
            if not "%%~dpI"=="%CURRENT_DIR%" (
                endlocal
                "%%I" %*
                exit /b %errorlevel%
            )
        )
    )
    echo airlock shim: unable to locate host {{TOOL}} outside of %CURRENT_DIR% >&2
    exit /b 127
)
endlocal

airlock.exe run -- {{TOOL}} %*
`

func generateWindowsCmdScript(tool string) string {
	return strings.ReplaceAll(windowsCmdTemplate, "{{TOOL}}", tool)
}
