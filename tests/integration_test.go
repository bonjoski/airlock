package tests

import (
	"bytes"
	"context"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/env"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/scratch"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

// TestSEC01_SSHReadDenial verifies that reading SSH keys is denied (V-01).
func TestSEC01_SSHReadDenial(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}

	tempDir := t.TempDir()
	mockHome := filepath.Join(tempDir, "home")
	workspace := filepath.Join(tempDir, "workspace")
	scratchDir := filepath.Join(tempDir, "scratch")

	_ = os.Mkdir(mockHome, 0700)
	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratchDir, 0700)

	sshKey := filepath.Join(mockHome, ".ssh", "id_rsa")
	_ = os.Mkdir(filepath.Join(mockHome, ".ssh"), 0700)
	_ = os.WriteFile(sshKey, []byte("SUPER_SECRET_KEY"), 0600)

	p := seatbelt.Params{
		UserHome:      mockHome,
		WorkspaceRoot: workspace,
		ScratchDir:    scratchDir,
		Airgap:        true,
	}

	gen := seatbelt.NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Failed to generate profile: %v", err)
	}

	cmd := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", sshKey)
	if err := cmd.Run(); err == nil {
		t.Errorf("SEC-01 FAILED: Expected reading %s to be denied", sshKey)
	}
}

// TestSEC03_GitHookPersistenceDenial verifies that writing to .git/hooks is denied (V-03).
func TestSEC03_GitHookPersistenceDenial(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	scratchDir := filepath.Join(tempDir, "scratch")

	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratchDir, 0700)

	gitHooks := filepath.Join(workspace, ".git", "hooks")
	_ = os.MkdirAll(gitHooks, 0755)

	p := seatbelt.Params{
		WorkspaceRoot: workspace,
		ScratchDir:    scratchDir,
		Airgap:        true,
	}

	gen := seatbelt.NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Failed to generate profile: %v", err)
	}

	trojan := filepath.Join(gitHooks, "pre-commit")
	cmd := exec.Command("sandbox-exec", "-p", profile, "/usr/bin/touch", trojan)
	if err := cmd.Run(); err == nil {
		t.Errorf("SEC-03 FAILED: Expected writing to .git/hooks to be denied")
	}
}

// TestSEC04_WorkspaceSecretDenial verifies that reading .env in workspace is denied (V-04).
func TestSEC04_WorkspaceSecretDenial(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	scratchDir := filepath.Join(tempDir, "scratch")

	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratchDir, 0700)

	envFile := filepath.Join(workspace, ".env")
	_ = os.WriteFile(envFile, []byte("SECRET=123"), 0600)

	p := seatbelt.Params{
		WorkspaceRoot: workspace,
		ScratchDir:    scratchDir,
		Airgap:        true,
	}

	gen := seatbelt.NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Failed to generate profile: %v", err)
	}

	cmd := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", envFile)
	if err := cmd.Run(); err == nil {
		t.Errorf("SEC-04 FAILED: Expected reading workspace .env to be denied")
	}
}

// TestSEC05_EnvSanitization verifies that parent shell secrets are stripped (V-07).
func TestSEC05_EnvSanitization(t *testing.T) {
	hostEnv := []string{
		"AWS_SECRET_ACCESS_KEY=secret_aws_key",
		"DATABASE_URL=postgres://user:pass@db:5432/prod",
		"GITHUB_TOKEN=ghp_secret_token",
		"PATH=/usr/bin:.:./bin:/bin",
		"TERM=xterm",
		"LANG=en_US.UTF-8",
	}

	sanitizer := env.NewSanitizer(env.Config{})
	sanitized := sanitizer.Sanitize(hostEnv)

	for _, entry := range sanitized {
		if strings.HasPrefix(entry, "AWS_") ||
			strings.HasPrefix(entry, "DATABASE_URL=") ||
			strings.HasPrefix(entry, "GITHUB_TOKEN=") {
			t.Errorf("SEC-05 FAILED: Sensitive variable leaked: %s", entry)
		}
	}
}

// TestSEC08_ExitCodePropagation verifies that the target command's exit code is returned.
func TestSEC08_ExitCodePropagation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("macOS only")
	}

	tempDir := t.TempDir()
	opts := sandbox.Options{
		WorkspaceRoot:  tempDir,
		Airgap:         true,
		NonInteractive: true,
	}

	eng, err := sandbox.NewEngine(opts)
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	code, err := eng.Execute(context.Background(), []string{"/bin/sh", "-c", "exit 37"})
	if err != nil {
		t.Fatalf("Execute returned unexpected error: %v", err)
	}
	if code != 37 {
		t.Errorf("SEC-08 FAILED: Expected exit code 37, got %d", code)
	}
}

// TestSEC11_ProxyDomainWhitelisting verifies that the forward proxy rejects unapproved domains (V-02).
func TestSEC11_ProxyDomainWhitelisting(t *testing.T) {
	prx, err := proxy.New([]string{})
	if err != nil {
		t.Fatalf("Failed to start proxy: %v", err)
	}
	defer prx.Close()

	conn, err := net.Dial("tcp", prx.URL()[7:]) // strip http://
	if err != nil {
		t.Fatalf("Failed to connect to proxy: %v", err)
	}
	defer conn.Close()

	_, _ = conn.Write([]byte("CONNECT evil.c2.attacker.com:443 HTTP/1.1\r\nHost: evil.c2.attacker.com:443\r\n\r\n"))
	var resp bytes.Buffer
	buf := make([]byte, 256)
	_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
	n, _ := conn.Read(buf)
	resp.Write(buf[:n])

	if !strings.Contains(resp.String(), "403 Forbidden") {
		t.Errorf("SEC-11 FAILED: Expected 403 Forbidden for untrusted domain, got: %s", resp.String())
	}
}

// TestSEC12_ScratchOrphanCleanup verifies that orphaned directories are scavenged (V-11).
func TestSEC12_ScratchOrphanCleanup(t *testing.T) {
	tempBase := t.TempDir()

	orphan := filepath.Join(tempBase, "boxpkg-deadbeef12345678")
	_ = os.Mkdir(orphan, 0700)
	oldTime := time.Now().Add(-48 * time.Hour)
	_ = os.Chtimes(orphan, oldTime, oldTime)

	cleaned, err := scratch.ScavengeOrphans(tempBase, 24*time.Hour)
	if err != nil {
		t.Fatalf("ScavengeOrphans error: %v", err)
	}
	if cleaned != 1 {
		t.Errorf("SEC-12 FAILED: Expected 1 orphan cleaned, got %d", cleaned)
	}
	if _, err := os.Stat(orphan); !os.IsNotExist(err) {
		t.Errorf("SEC-12 FAILED: Orphan directory still exists on disk")
	}
}
