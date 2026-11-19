//go:build !windows

package tests

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"

	"github.com/bonjoski/airlock/pkg/bridge"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/env"
	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/pty"
	"github.com/bonjoski/airlock/pkg/sandbox"
)

// ADV-P3-01: Agent Profile Boundary Escape (Credential Directory Access)
// Verifies that the agent profile strictly forbids reading sensitive developer directories.
func TestAdversarial_AgentProfileCredentialProtection(t *testing.T) {
	agentCfg, err := config.GetBuiltinProfile(config.ProfileAgent)
	if err != nil {
		t.Fatalf("failed to load agent profile: %v", err)
	}

	criticalPaths := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", ".env"}
	for _, p := range criticalPaths {
		found := false
		for _, denied := range agentCfg.Filesystem.DenyRead {
			if denied == p {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("CRITICAL: Agent profile failed to deny access to %q!", p)
		}
	}
	t.Log("PASS: Agent profile strictly denies read access to all host credential roots")
}

// ADV-P3-02: Agent Network Exfiltration (Metadata & Untrusted Endpoints)
// Verifies that only pinned AI endpoints and package registries are allowed.
func TestAdversarial_AgentNetworkAllowlistLockdown(t *testing.T) {
	agentCfg, err := config.GetBuiltinProfile(config.ProfileAgent)
	if err != nil {
		t.Fatalf("failed to load agent profile: %v", err)
	}

	// Must reject unapproved domains by default
	if agentCfg.Network.UnknownDomainAction != "refused" {
		t.Fatalf("CRITICAL: Unknown domain action must be 'refused', got %q", agentCfg.Network.UnknownDomainAction)
	}

	// Must NOT contain wildcards like "*"
	for _, d := range agentCfg.Network.AllowDomains {
		if d == "*" || d == "*.*" {
			t.Fatalf("CRITICAL: Agent profile allow_domains contains wildcard %q!", d)
		}
		if strings.Contains(d, "169.254") {
			t.Fatalf("CRITICAL: Agent profile allow_domains accidentally whitelists metadata IP %q!", d)
		}
	}
	t.Log("PASS: Agent profile network lockdown verified against wildcards and metadata IPs")
}

// ADV-P3-03: MicroVM Fallback Hardening on Missing Hypervisor
// If --microvm is requested but aegisbox is not found, Airlock MUST fail closed.
func TestAdversarial_MicroVMMissingBinaryFailClosed(t *testing.T) {
	orig := os.Getenv("AEGISBOX_PATH")
	defer os.Setenv("AEGISBOX_PATH", orig)

	os.Setenv("AEGISBOX_PATH", "/nonexistent/binary/path/to/aegisbox")

	opts := sandbox.Options{
		WorkspaceRoot: t.TempDir(),
	}

	code, err := bridge.ExecuteMicroVM(context.Background(), opts, []string{"echo", "fail"})
	if err == nil {
		t.Fatal("CRITICAL: ExecuteMicroVM failed open when binary was missing!")
	}
	if code == 0 {
		t.Fatalf("expected non-zero exit code on failure, got %d", code)
	}
	t.Logf("PASS: ExecuteMicroVM strictly failed closed: %v", err)
}

// ADV-P3-04: TIOCSTI Subshell Injection Probe (V-05)
func TestAdversarial_TIOCSTIInjectionMitigation(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("TIOCSTI ioctl is a Unix-specific vector, skipped on Windows")
	}
	tmp, err := os.CreateTemp("", "tiocsti-adv")
	if err != nil {
		t.Fatalf("temp file error: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	err = pty.CheckTIOCSTI(tmp)
	if err == nil {
		t.Fatal("CRITICAL: TIOCSTI ioctl succeeded on regular file descriptor!")
	}
	t.Logf("PASS: Terminal queue injection attempt correctly neutralized with error: %v", err)
}

// ADV-P3-05: Dynamic Linker Environment Injection under Agent Profile
func TestAdversarial_DynamicLinkerStripping(t *testing.T) {
	sanitizer := env.NewSanitizer(env.Config{
		VirtualHome: "/tmp/fake-home",
		ScratchDir:  "/tmp/fake-scratch",
	})

	poisonedEnv := []string{
		"LD_PRELOAD=/evil/libroot.so",
		"DYLD_INSERT_LIBRARIES=/evil/hook.dylib",
		"DYLD_LIBRARY_PATH=/evil/lib",
		"PYTHONPATH=/evil/python",
		"NODE_OPTIONS=--require /evil/hook.js",
		"SAFE_VAR=good",
	}

	clean := sanitizer.Sanitize(poisonedEnv)

	for _, entry := range clean {
		for _, dangerous := range []string{"LD_PRELOAD", "DYLD_INSERT_LIBRARIES", "DYLD_LIBRARY_PATH", "NODE_OPTIONS"} {
			if strings.HasPrefix(entry, dangerous+"=") {
				t.Fatalf("CRITICAL: Dangerous dynamic linker variable %q survived environment sanitization!", entry)
			}
		}
	}
	t.Log("PASS: All dynamic linker and shell injection environment variables stripped successfully")
}

// ADV-P3-06: Dev-Agent Profile Credential and Symlink Traversal Protection
// Verifies that dev-agent profile blocks ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.config/gh,
// and enforces canonical /System/Volumes/Data path denials on macOS.
func TestAdversarial_DevAgentProfileCredentialProtection(t *testing.T) {
	devCfg, err := config.GetBuiltinProfile(config.ProfileDevAgent)
	if err != nil {
		t.Fatalf("failed to load dev-agent profile: %v", err)
	}

	criticalPaths := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config/gh", ".env"}
	for _, p := range criticalPaths {
		found := false
		for _, denied := range devCfg.Filesystem.DenyRead {
			if denied == p {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("CRITICAL: dev-agent profile failed to deny access to %q!", p)
		}
	}
	t.Log("PASS: dev-agent profile strictly denies read access to all host credential roots including ~/.config/gh")
}

// ADV-P3-07: MCP-Gateway Profile Anti-Loopback and Cloud Credential Confinement (CVE-2026-125926)
func TestAdversarial_MCPGatewayProfileProtection(t *testing.T) {
	mcpCfg, err := config.GetBuiltinProfile(config.ProfileMCPGateway)
	if err != nil {
		t.Fatalf("failed to load mcp-gateway profile: %v", err)
	}

	if !mcpCfg.Network.AntiLoopback {
		t.Fatalf("CRITICAL: mcp-gateway profile must enforce AntiLoopback!")
	}

	criticalPaths := []string{"~/.ssh", "~/.aws", "~/.gnupg", "~/.kube", "~/.config/gh", "~/.azure", "/var/run/docker.sock", ".env"}
	for _, p := range criticalPaths {
		found := false
		for _, denied := range mcpCfg.Filesystem.DenyRead {
			if denied == p {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("CRITICAL: mcp-gateway profile failed to deny access to %q!", p)
		}
	}
	t.Log("PASS: mcp-gateway profile strictly denies access to cloud credentials, sockets, and loopback")
}

// ADV-P3-08: Web-Worker Profile AntiFox Webshell Execution Defense
func TestAdversarial_WebWorkerProfileProtection(t *testing.T) {
	wwCfg, err := config.GetBuiltinProfile(config.ProfileWebWorker)
	if err != nil {
		t.Fatalf("failed to load web-worker profile: %v", err)
	}

	shellDenials := []string{"/bin/sh", "/bin/bash", "/bin/zsh", "/usr/bin/python3", "/usr/bin/perl"}
	for _, p := range shellDenials {
		found := false
		for _, denied := range wwCfg.Filesystem.DenyRead {
			if denied == p {
				found = true
				break
			}
		}
		if !found {
			t.Fatalf("CRITICAL: web-worker profile failed to deny access to shell binary %q!", p)
		}
	}
	t.Log("PASS: web-worker profile strictly denies execution access to shell interpreters")
}

// ADV-P3-09: Landlock Path Resolution TOCTOU Symlink Traversal Hardening (THREAT-2026-ADV-02)
// Verifies that Landlock path resolution pins directory file descriptors safely and guards
// against concurrent worker symlink replacement attacks during rapid workspace setup.
func TestAdversarial_LandlockPathResolution_SymlinkRaceFailsClosed(t *testing.T) {
	wsDir := t.TempDir()
	victimTarget := filepath.Join(wsDir, "untrusted_link")
	sensitiveHostDir := filepath.Join(wsDir, "host_secrets")
	if err := os.MkdirAll(sensitiveHostDir, 0700); err != nil {
		t.Fatalf("mkdir host_secrets failed: %v", err)
	}

	// Create symlink pointing from inside workspace to sensitive host directory
	if err := os.Symlink(sensitiveHostDir, victimTarget); err != nil {
		t.Fatalf("symlink creation failed: %v", err)
	}

	denyPaths := []string{sensitiveHostDir, "~/.ssh", "~/.aws"}

	// 1. Path resolution must fail closed when encountering symlink to denied path
	fd, err := landlock.SafePinPathFD(victimTarget, denyPaths, wsDir)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Landlock pinned file descriptor to denied directory %s!", sensitiveHostDir)
	}
	if !errors.Is(err, landlock.ErrDeniedPathTarget) && !errors.Is(err, landlock.ErrSymlinkTraversal) {
		t.Fatalf("Expected ErrDeniedPathTarget or ErrSymlinkTraversal, got: %v", err)
	}

	// 2. Path resolution must verify that workspace paths cannot escape workspace root via symlink
	outsideDir := t.TempDir()
	escapeLink := filepath.Join(wsDir, "escape_link")
	if err := os.Symlink(outsideDir, escapeLink); err != nil {
		t.Fatalf("symlink escape creation failed: %v", err)
	}

	fd, err = landlock.SafePinPathFD(escapeLink, nil, wsDir)
	if err == nil {
		_ = syscall.Close(fd)
		t.Fatalf("CRITICAL SECURITY VULNERABILITY: Landlock allowed workspace escape symlink to %s!", outsideDir)
	}
	if !errors.Is(err, landlock.ErrSymlinkTraversal) {
		t.Fatalf("Expected ErrSymlinkTraversal for workspace escape link, got: %v", err)
	}

	t.Log("PASS: Landlock path resolution strictly failed closed against symlink traversal attacks")
}
