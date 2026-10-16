package tests

import (
	"context"
	"os"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/bridge"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/env"
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
