package seatbelt

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestProfileGenerator_Generate(t *testing.T) {
	p := Params{
		UserHome:      "/Users/testuser",
		WorkspaceRoot: "/Users/testuser/projects/demo",
		ScratchDir:    "/tmp/airlock-abcdef123456",
		ProxyPort:     18443,
	}

	gen := NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 1. Must NOT contain literal wildcard subpaths (V-01)
	if strings.Contains(profile, `subpath "/Users/*/.ssh"`) {
		t.Errorf("Profile contains broken wildcard subpath /Users/*/.ssh")
	}

	// 2. Must contain dynamic user home path (V-01)
	if !strings.Contains(profile, `subpath "/Users/testuser/.ssh"`) {
		t.Errorf("Profile does not contain expanded user home path")
	}

	// 3. Must deny Mach lookups for securityd, launchservicesd, pasteboard, tccd (V-10)
	for _, mach := range []string{
		`"com.apple.securityd"`,
		`"com.apple.coreservices.launchservicesd"`,
		`"com.apple.pasteboard.pboard"`,
		`"com.apple.tccd"`,
	} {
		if !strings.Contains(profile, mach) {
			t.Errorf("Profile missing Mach deny rule for %s", mach)
		}
	}

	// 4. Must protect .git from write (V-03)
	if !strings.Contains(profile, `(subpath "/Users/testuser/projects/demo/.git")`) {
		t.Errorf("Profile missing .git write denial")
	}

	// 5. Must mask .env from read (V-04)
	if !strings.Contains(profile, `(subpath "/Users/testuser/projects/demo/.env")`) {
		t.Errorf("Profile missing .env read denial")
	}

	// 6. Must permit proxy port on loopback (V-02)
	if !strings.Contains(profile, `(allow network-outbound (to tcp "localhost:18443"))`) {
		t.Errorf("Profile missing proxy port outbound allowance")
	}

	// 7. Must permit trustd for system trust settings evaluation (F2)
	if !strings.Contains(profile, `"com.apple.trustd.agent"`) {
		t.Errorf("Profile missing trustd.agent allow rule")
	}

	// 8. Must allow file-lock and ipc-posix-shm (F4)
	if !strings.Contains(profile, `(allow file-lock)`) {
		t.Errorf("Profile missing file-lock allowance")
	}

	// 9. Must permit CA certificate bundles inside workspace (F3)
	if !strings.Contains(profile, `cacert\.pem`) {
		t.Errorf("Profile missing cacert.pem allowance rule")
	}
}

// TestLiveSeatbeltCompilation verifies that the profile compiles cleanly
// and enforces expected restrictions with sandbox-exec on macOS.
func TestLiveSeatbeltCompilation(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS Seatbelt live test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	scratch := filepath.Join(tempDir, "scratch")
	mockHome := filepath.Join(tempDir, "mock_home")

	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratch, 0700)
	_ = os.Mkdir(mockHome, 0700)

	// Create mock secret
	sshDir := filepath.Join(mockHome, ".ssh")
	_ = os.Mkdir(sshDir, 0700)
	sshKey := filepath.Join(sshDir, "id_rsa")
	_ = os.WriteFile(sshKey, []byte("TOP_SECRET_SSH_KEY"), 0600)

	// Create mock .git in workspace
	gitDir := filepath.Join(workspace, ".git")
	_ = os.Mkdir(gitDir, 0755)
	hooksDir := filepath.Join(gitDir, "hooks")
	_ = os.Mkdir(hooksDir, 0755)

	// Create mock .env in workspace
	envFile := filepath.Join(workspace, ".env")
	_ = os.WriteFile(envFile, []byte("DATABASE_URL=postgres://root:pass@db"), 0600)

	p := Params{
		UserHome:      mockHome,
		WorkspaceRoot: workspace,
		ScratchDir:    scratch,
		Airgap:        true,
	}

	gen := NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 1. Basic execution succeeds
	cmdEcho := exec.Command("sandbox-exec", "-p", profile, "/bin/echo", "seatbelt_compiled_successfully")
	output, err := cmdEcho.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox-exec failed to compile and run profile: %v\nOutput: %s", err, string(output))
	}
	if !strings.Contains(string(output), "seatbelt_compiled_successfully") {
		t.Errorf("Unexpected output: %s", string(output))
	}

	// 2. V-01: Reading mock .ssh/id_rsa is BLOCKED
	cmdSSH := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", sshKey)
	if err := cmdSSH.Run(); err == nil {
		t.Errorf("SECURITY VULNERABILITY: Sandboxed process successfully read %s! Expected denial.", sshKey)
	}

	// 3. V-04: Reading workspace .env is BLOCKED
	cmdEnv := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", envFile)
	if err := cmdEnv.Run(); err == nil {
		t.Errorf("SECURITY VULNERABILITY: Sandboxed process successfully read %s! Expected denial.", envFile)
	}

	// 4. V-03: Writing to .git/hooks is BLOCKED
	trojanHook := filepath.Join(hooksDir, "pre-commit")
	cmdHook := exec.Command("sandbox-exec", "-p", profile, "/usr/bin/touch", trojanHook)
	if err := cmdHook.Run(); err == nil {
		t.Errorf("SECURITY VULNERABILITY: Sandboxed process successfully wrote to %s! Expected denial.", trojanHook)
	}

	// 5. Valid write to workspace succeeds
	validFile := filepath.Join(workspace, "valid_build_artifact.txt")
	cmdValid := exec.Command("sandbox-exec", "-p", profile, "/usr/bin/touch", validFile)
	if err := cmdValid.Run(); err != nil {
		t.Errorf("Normal workspace write failed unexpectedly: %v", err)
	}
}

func TestProfileGenerator_GenerateDevAgent(t *testing.T) {
	p := Params{
		Profile:       "dev-agent",
		UserHome:      "/Users/testuser",
		WorkspaceRoot: "/Users/testuser/projects/agent-work",
		ScratchDir:    "/tmp/airlock-agent123",
		ProxyPort:     18443,
	}

	gen := NewGenerator()
	profile, err := gen.GenerateDevAgent(p)
	if err != nil {
		t.Fatalf("GenerateDevAgent failed: %v", err)
	}

	// 1. Must explicitly deny ~/.ssh, ~/.aws, ~/.gnupg, ~/.kube, ~/.config/gh, ~/.config/gcloud
	requiredDenies := []string{
		`subpath "/Users/testuser/.ssh"`,
		`subpath "/Users/testuser/.aws"`,
		`subpath "/Users/testuser/.gnupg"`,
		`subpath "/Users/testuser/.kube"`,
		`subpath "/Users/testuser/.config/gh"`,
		`subpath "/Users/testuser/.config/gcloud"`,
	}
	for _, d := range requiredDenies {
		if !strings.Contains(profile, d) {
			t.Errorf("dev-agent profile missing denial for: %s", d)
		}
	}

	// 2. Must include canonical Data volume denial (/System/Volumes/Data/Users/...)
	dataVolumeDeny := `subpath "/System/Volumes/Data/Users/testuser/.ssh"`
	if !strings.Contains(profile, dataVolumeDeny) {
		t.Errorf("dev-agent profile missing canonical data volume denial: %s", dataVolumeDeny)
	}

	// 3. Must deny process introspection
	if !strings.Contains(profile, `(deny process-info* (target others))`) {
		t.Errorf("dev-agent profile missing process-info denial")
	}

	// 4. Must deny execution of /usr/bin/security (Keychain CLI)
	if !strings.Contains(profile, `(literal "/usr/bin/security")`) {
		t.Errorf("dev-agent profile missing /usr/bin/security denial")
	}

	// 5. Must mask workspace secrets (.env, etc.)
	if !strings.Contains(profile, `secrets\.json`) {
		t.Errorf("dev-agent profile missing secrets.json mask")
	}
}

func TestLiveSeatbeltCompilation_DevAgent(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping macOS Seatbelt live test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	scratch := filepath.Join(tempDir, "scratch")
	mockHome := filepath.Join(tempDir, "mock_home")

	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratch, 0700)
	_ = os.Mkdir(mockHome, 0700)

	// Mock credentials
	sshDir := filepath.Join(mockHome, ".ssh")
	_ = os.Mkdir(sshDir, 0700)
	sshKey := filepath.Join(sshDir, "id_rsa")
	_ = os.WriteFile(sshKey, []byte("DEV_AGENT_SSH_SECRET"), 0600)

	awsDir := filepath.Join(mockHome, ".aws")
	_ = os.Mkdir(awsDir, 0700)
	awsCred := filepath.Join(awsDir, "credentials")
	_ = os.WriteFile(awsCred, []byte("[default]\naws_access_key_id=test"), 0600)

	ghDir := filepath.Join(mockHome, ".config", "gh")
	_ = os.MkdirAll(ghDir, 0700)
	ghHosts := filepath.Join(ghDir, "hosts.yml")
	_ = os.WriteFile(ghHosts, []byte("github.com:\n  oauth_token: gho_secret"), 0600)

	p := Params{
		Profile:       "dev-agent",
		UserHome:      mockHome,
		WorkspaceRoot: workspace,
		ScratchDir:    scratch,
		Airgap:        true,
	}

	gen := NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 1. Basic command runs
	cmdEcho := exec.Command("sandbox-exec", "-p", profile, "/bin/echo", "dev_agent_ok")
	output, err := cmdEcho.CombinedOutput()
	if err != nil {
		t.Fatalf("sandbox-exec failed for dev-agent: %v\nOutput: %s", err, string(output))
	}
	if !strings.Contains(string(output), "dev_agent_ok") {
		t.Errorf("Unexpected output: %s", string(output))
	}

	// 2. Deny read of ~/.ssh/id_rsa
	cmdSSH := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", sshKey)
	if err := cmdSSH.Run(); err == nil {
		t.Errorf("SECURITY VULNERABILITY: dev-agent read %s! Expected denial.", sshKey)
	}

	// 3. Deny read of ~/.aws/credentials
	cmdAWS := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", awsCred)
	if err := cmdAWS.Run(); err == nil {
		t.Errorf("SECURITY VULNERABILITY: dev-agent read %s! Expected denial.", awsCred)
	}

	// 4. Deny read of ~/.config/gh/hosts.yml
	cmdGH := exec.Command("sandbox-exec", "-p", profile, "/bin/cat", ghHosts)
	if err := cmdGH.Run(); err == nil {
		t.Errorf("SECURITY VULNERABILITY: dev-agent read %s! Expected denial.", ghHosts)
	}
}
