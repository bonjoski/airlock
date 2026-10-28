package tests

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/doctor"
	"github.com/bonjoski/airlock/pkg/env"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

// TestSEC33_AdvisoryRemediations_Adversarial verifies security invariants and defenses
// implemented in response to GHSA-3vmj-37wh-72q5 across toolchain ecosystems (SEC-33).
func TestSEC33_AdvisoryRemediations_Adversarial(t *testing.T) {
	// ADV-SEC33-01: Working Directory Traversal Hardening (F1)
	// Verifies that while subdirectories preserve working directory, sandbox writes
	// outside WorkspaceRoot remain strictly blocked.
	t.Run("ADV_SEC33_01_WorkingDirRelocationAndWriteIsolation", func(t *testing.T) {
		tempDir := t.TempDir()
		workspaceRoot := filepath.Join(tempDir, "workspace")
		subdir := filepath.Join(workspaceRoot, "nested", "pkg")
		outsideDir := filepath.Join(tempDir, "outside_target")

		if err := os.MkdirAll(subdir, 0755); err != nil {
			t.Fatalf("failed to create subdir: %v", err)
		}
		if err := os.MkdirAll(outsideDir, 0755); err != nil {
			t.Fatalf("failed to create outside dir: %v", err)
		}

		var stdoutBuf bytes.Buffer
		opts := sandbox.Options{
			WorkspaceRoot:  workspaceRoot,
			WorkingDir:     subdir,
			Airgap:         true,
			NonInteractive: true,
			Stdout:         &stdoutBuf,
			Stderr:         &stdoutBuf,
		}

		eng, err := sandbox.NewEngine(opts)
		if err != nil {
			if errors.Is(err, sandbox.ErrBwrapNotFound) || errors.Is(err, sandbox.ErrUsernsDisabled) {
				t.Skip("bwrap not found or unprivileged userns disabled; skipping host execution")
			}
			t.Fatalf("failed to create sandbox engine: %v", err)
		}

		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()

		// 1. Verify working directory is preserved
		pwdCmd := PlatformCmd("pwd")
		if runtime.GOOS == "windows" {
			pwdCmd = []string{"cmd.exe", "/c", "cd"}
		}
		code, err := eng.Execute(ctx, pwdCmd)
		if err != nil || code != 0 {
			t.Fatalf("failed to execute pwd: %v (code %d)", err, code)
		}
		output := strings.TrimSpace(stdoutBuf.String())
		cleanSubdir := filepath.Clean(subdir)
		cleanOutput := filepath.Clean(output)
		if !strings.HasSuffix(cleanOutput, filepath.Base(cleanSubdir)) && !strings.Contains(cleanOutput, "pkg") {
			t.Fatalf("ADV-SEC33-01 VIOLATION: Working directory not preserved, got %q (expected %q)", cleanOutput, cleanSubdir)
		}

		// 2. Adversarial attempt: Attempting to write a trojan file outside the workspace root MUST fail
		escapeFile := filepath.Join(outsideDir, "escape.txt")
		writeCmd := PlatformCmd("sh", "-c", "echo pwned > "+escapeFile)
		if runtime.GOOS == "windows" {
			writeCmd = []string{"cmd.exe", "/c", "echo pwned > " + escapeFile}
		}
		code, _ = eng.Execute(ctx, writeCmd)
		if _, statErr := os.Stat(escapeFile); statErr == nil {
			t.Fatalf("CRITICAL ADV-SEC33-01 VIOLATION: Sandboxed command wrote outside WorkspaceRoot to %s!", escapeFile)
		}
		t.Log("PASS: ADV-SEC33-01 WorkingDir relocation verified and write isolation maintained")
	})

	// ADV-SEC33-02: macOS Trust Settings & Keychain Secrets Isolation (F2)
	// Verifies that while com.apple.trustd.agent Mach lookup is permitted for cert evaluation,
	// com.apple.securityd Mach lookup and Keychain secret access are strictly denied.
	t.Run("ADV_SEC33_02_MacOSTrustIsolation_KeychainProtected", func(t *testing.T) {
		tempDir := t.TempDir()
		gen := seatbelt.NewGenerator()
		sbpl, err := gen.Generate(seatbelt.Params{
			UserHome:      "/Users/testuser",
			WorkspaceRoot: tempDir,
			ScratchDir:    filepath.Join(tempDir, "scratch"),
			ProxyPort:     18443,
		})
		if err != nil {
			t.Fatalf("failed to generate seatbelt profile: %v", err)
		}

		// 1. Must allow trustd for system cert validation
		if !strings.Contains(sbpl, `"com.apple.trustd.agent"`) {
			t.Fatal("ADV-SEC33-02 VIOLATION: com.apple.trustd.agent missing from seatbelt profile")
		}

		// 2. Must NOT allow com.apple.securityd (Keychain access)
		// It must be present in the deny block and absent from the allow block
		allowBlockIdx := strings.Index(sbpl, "(allow mach-lookup")
		if allowBlockIdx != -1 {
			allowBlock := sbpl[allowBlockIdx:]
			if nextParen := strings.Index(allowBlock, "\n\n"); nextParen != -1 {
				allowBlock = allowBlock[:nextParen]
			}
			if strings.Contains(allowBlock, `"com.apple.securityd"`) {
				t.Fatal("CRITICAL ADV-SEC33-02 VIOLATION: com.apple.securityd Mach lookup inadvertently permitted!")
			}
		}

		denyBlockIdx := strings.Index(sbpl, "(deny mach-lookup")
		if denyBlockIdx == -1 || !strings.Contains(sbpl[denyBlockIdx:], `"com.apple.securityd"`) {
			t.Fatal("CRITICAL ADV-SEC33-02 VIOLATION: com.apple.securityd missing from mach-lookup deny block!")
		}

		// 3. On macOS host, verify host keychain reading is strictly denied
		if runtime.GOOS == "darwin" {
			var outBuf bytes.Buffer
			opts := sandbox.Options{
				WorkspaceRoot:  tempDir,
				Airgap:         true,
				NonInteractive: true,
				Stdout:         &outBuf,
				Stderr:         &outBuf,
			}
			eng, err := sandbox.NewEngine(opts)
			if err != nil {
				t.Fatalf("failed to initialize macOS engine: %v", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
			defer cancel()

			// Attempting to query keychain items via security command
			code, _ := eng.Execute(ctx, []string{"/usr/bin/security", "find-generic-password", "-s", "dummy-service"})
			// Exit code must be non-zero (either denied or failed)
			if code == 0 {
				t.Fatalf("CRITICAL ADV-SEC33-02 VIOLATION: Keychain query succeeded inside sandbox!")
			}
		}
		t.Log("PASS: ADV-SEC33-02 macOS trustd Mach lookup isolated; securityd/keychain protected")
	})

	// ADV-SEC33-03: Workspace CA Bundle Exemption vs Secret Key Lockdown (F3)
	// Verifies that while cacert.pem in virtualenvs is allowed, private keys and tokens
	// (*.pem, *.key) in the workspace remain masked and denied.
	t.Run("ADV_SEC33_03_CABundleExempt_SecretKeysLockedDown", func(t *testing.T) {
		tempDir := t.TempDir()

		// 1. Create a legitimate venv CA bundle
		certifiDir := filepath.Join(tempDir, ".venv", "lib", "python3.11", "site-packages", "certifi")
		if err := os.MkdirAll(certifiDir, 0755); err != nil {
			t.Fatalf("failed to create certifi dir: %v", err)
		}
		if err := os.WriteFile(filepath.Join(certifiDir, "cacert.pem"), []byte("---BEGIN CERTIFICATE---\nMOCK_CA\n---END CERTIFICATE---"), 0644); err != nil {
			t.Fatalf("failed to write cacert.pem: %v", err)
		}

		// 2. Create adversarial private secret files in workspace
		secretFiles := []string{
			"id_rsa.pem",
			"server.key",
			"client_secret.pem",
			"private.pem",
		}
		for _, sf := range secretFiles {
			if err := os.WriteFile(filepath.Join(tempDir, sf), []byte("---BEGIN PRIVATE KEY---\nTOP_SECRET\n---END PRIVATE KEY---"), 0600); err != nil {
				t.Fatalf("failed to write %s: %v", sf, err)
			}
		}

		// 3. Test Linux FindWorkspaceSecrets masking
		secrets, err := sandbox.FindWorkspaceSecrets(tempDir)
		if err != nil {
			t.Fatalf("FindWorkspaceSecrets failed: %v", err)
		}

		secretMap := make(map[string]bool)
		for _, s := range secrets {
			secretMap[filepath.Base(s)] = true
		}

		// cacert.pem MUST NOT be masked
		if secretMap["cacert.pem"] {
			t.Fatal("ADV-SEC33-03 VIOLATION: cacert.pem was incorrectly flagged as secret!")
		}

		// Sensitive private keys MUST be masked
		for _, sf := range secretFiles {
			if !secretMap[sf] {
				t.Fatalf("CRITICAL ADV-SEC33-03 VIOLATION: Private key %s was NOT detected and masked by FindWorkspaceSecrets!", sf)
			}
		}

		// 4. Test macOS Seatbelt profile rule generation
		gen := seatbelt.NewGenerator()
		sbpl, err := gen.Generate(seatbelt.Params{
			UserHome:      "/Users/testuser",
			WorkspaceRoot: tempDir,
			ScratchDir:    filepath.Join(tempDir, "scratch"),
			ProxyPort:     18443,
		})
		if err != nil {
			t.Fatalf("failed to generate profile: %v", err)
		}

		if !strings.Contains(sbpl, "cacert") || !strings.Contains(sbpl, "ca-bundle") {
			t.Fatal("ADV-SEC33-03 VIOLATION: Seatbelt profile missing CA bundle exception regex")
		}
		if !strings.Contains(sbpl, `.*\.pem$`) || !strings.Contains(sbpl, `.*\.key$`) {
			t.Fatal("CRITICAL ADV-SEC33-03 VIOLATION: Seatbelt profile missing general .pem/.key denial!")
		}
		t.Log("PASS: ADV-SEC33-03 CA bundle exemption verified and private key secret masking intact")
	})

	// ADV-SEC33-04: /tmp Shared Memory & Launchd Socket Tamper Resistance (F4)
	// Verifies that while /tmp is writable for pnpm locking, com.apple.launchd.* sockets
	// remain strictly denied and cannot be read or hijacked.
	t.Run("ADV_SEC33_04_TmpLockingAllowed_LaunchdSocketsDenied", func(t *testing.T) {
		tempDir := t.TempDir()
		gen := seatbelt.NewGenerator()
		sbpl, err := gen.Generate(seatbelt.Params{
			UserHome:      "/Users/testuser",
			WorkspaceRoot: tempDir,
			ScratchDir:    filepath.Join(tempDir, "scratch"),
			ProxyPort:     18443,
		})
		if err != nil {
			t.Fatalf("failed to generate profile: %v", err)
		}

		// 1. Must allow file-lock and posix-shm for pnpm
		if !strings.Contains(sbpl, "(allow file-lock)") {
			t.Fatal("ADV-SEC33-04 VIOLATION: (allow file-lock) missing from seatbelt profile")
		}
		if !strings.Contains(sbpl, "(allow ipc-posix-shm*)") {
			t.Fatal("ADV-SEC33-04 VIOLATION: (allow ipc-posix-shm*) missing from seatbelt profile")
		}

		// 2. Launchd denial MUST appear after the /tmp allow rule in SBPL
		tmpAllowIdx := strings.Index(sbpl, `(subpath "/tmp")`)
		if tmpAllowIdx == -1 {
			t.Fatal("ADV-SEC33-04 VIOLATION: /tmp file-write allow rule missing")
		}

		launchdDenyIdx := strings.Index(sbpl, `com\.apple\.launchd`)
		if launchdDenyIdx == -1 {
			t.Fatal("CRITICAL ADV-SEC33-04 VIOLATION: launchd socket protection rule missing from seatbelt profile!")
		}

		if launchdDenyIdx < tmpAllowIdx {
			t.Fatal("CRITICAL ADV-SEC33-04 VIOLATION: launchd deny rule placed BEFORE /tmp allow rule; in SBPL later rules override!")
		}
		t.Log("PASS: ADV-SEC33-04 /tmp write allowed for pnpm while launchd sockets strictly protected")
	})

	// ADV-SEC33-05: Ecosystem Cache Environment Poisoning Defense
	// Verifies that host environment variables pointing caches to sensitive host paths
	// are purged and redirected to isolated staging directory.
	t.Run("ADV_SEC33_05_EcosystemCacheEnvironmentPoisoningDefense", func(t *testing.T) {
		stagingCache := "/isolated/staging/cache"
		sanitizer := env.NewSanitizer(env.Config{
			VirtualHome:  "/virtual/home",
			ScratchDir:   "/virtual/tmp",
			StagingCache: stagingCache,
		})

		// Adversary attempts to point cache directories to host credentials
		hostEnv := []string{
			"GRADLE_USER_HOME=/Users/victim/.ssh",
			"MAVEN_OPTS=-Duser.home=/etc -Dsensitive=true",
			"DOTNET_CLI_HOME=/Users/victim/.aws",
			"NUGET_PACKAGES=/Users/victim/.kube",
			"GEM_HOME=/Users/victim/.gnupg",
			"BUNDLE_PATH=/root/.ssh",
			"SWIFTPM_CACHE_DIR=/Users/victim/secrets",
			"CP_CACHE_DIR=/Users/victim/Library/Keychains",
			"HELM_CACHE_HOME=/etc/kubernetes",
			"pnpm_config_store_dir=/etc/shadow",
			"SAFE_VAR=ok",
		}

		sanitized := sanitizer.Sanitize(hostEnv)
		envMap := make(map[string]string)
		for _, e := range sanitized {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}

		// Verify that all cache variables point strictly inside stagingCache
		checkVars := []string{
			"GRADLE_USER_HOME",
			"DOTNET_CLI_HOME",
			"NUGET_PACKAGES",
			"GEM_HOME",
			"BUNDLE_PATH",
			"SWIFTPM_CACHE_DIR",
			"CP_CACHE_DIR",
			"HELM_CACHE_HOME",
			"pnpm_config_store_dir",
		}

		for _, v := range checkVars {
			val, exists := envMap[v]
			if !exists {
				t.Fatalf("ADV-SEC33-05 VIOLATION: Expected %s in sanitized env", v)
			}
			if !strings.HasPrefix(val, stagingCache) {
				t.Fatalf("CRITICAL ADV-SEC33-05 VIOLATION: %s leaked or escaped staging cache! Got %q (expected prefix %q)", v, val, stagingCache)
			}
		}

		// Verify MAVEN_OPTS uses staging cache local repo
		mavenOpts := envMap["MAVEN_OPTS"]
		if !strings.Contains(mavenOpts, stagingCache) || strings.Contains(mavenOpts, "/etc") {
			t.Fatalf("CRITICAL ADV-SEC33-05 VIOLATION: MAVEN_OPTS host poisoning survived: %q", mavenOpts)
		}
		t.Log("PASS: ADV-SEC33-05 Toolchain cache variables protected from host path injection")
	})

	// ADV-SEC33-06: Toolchain Shim & Binary Shadowing Detection (F5 & F6)
	// Verifies that doctor diagnostics identify both internal shim directory shadowing
	// and external PATH duplicate binary collisions.
	t.Run("ADV_SEC33_06_ShimShadowingDetection", func(t *testing.T) {
		ctx := context.Background()
		tempDir := t.TempDir()

		shimDir := filepath.Join(tempDir, "shims")
		binHomebrew := filepath.Join(tempDir, "brew", "bin")
		binLegacy := filepath.Join(tempDir, "legacy", "bin")

		_ = os.MkdirAll(shimDir, 0755)
		_ = os.MkdirAll(binHomebrew, 0755)
		_ = os.MkdirAll(binLegacy, 0755)

		airlockBinName := "airlock"
		if runtime.GOOS == "windows" {
			airlockBinName += ".exe"
		}

		// 1. Plant an airlock binary inside shim directory
		_ = os.WriteFile(filepath.Join(shimDir, airlockBinName), []byte("#!/bin/sh\nexit 0\n"), 0755)

		// 2. Plant airlock in two PATH locations
		_ = os.WriteFile(filepath.Join(binHomebrew, airlockBinName), []byte("#!/bin/sh\nexit 0\n"), 0755)
		_ = os.WriteFile(filepath.Join(binLegacy, airlockBinName), []byte("#!/bin/sh\nexit 0\n"), 0755)

		pathEnv := strings.Join([]string{binHomebrew, binLegacy}, string(os.PathListSeparator))

		results := doctor.CheckToolchainShims(ctx, doctor.Options{
			ShimDir: shimDir,
			PathEnv: pathEnv,
		})

		var caughtShimShadow, caughtPathShadow bool
		for _, res := range results {
			if res.ID == "shims-shadowing-airlock" {
				caughtShimShadow = true
			}
			if res.ID == "shims-path-shadowing" {
				caughtPathShadow = true
			}
		}

		if !caughtShimShadow {
			t.Fatal("ADV-SEC33-06 VIOLATION: Doctor failed to flag airlock binary inside shim directory!")
		}
		if !caughtPathShadow {
			t.Fatal("ADV-SEC33-06 VIOLATION: Doctor failed to flag multiple airlock binaries in $PATH!")
		}
		t.Log("PASS: ADV-SEC33-06 Shim and PATH shadowing diagnostics caught collisions accurately")
	})

	// ADV-SEC33-07: Corporate Artifact Mirror Lockdown
	// Verifies that enterprise configurations can lockdown network egress to corporate
	// artifact repositories (Artifactory, Nexus) while refusing untrusted public registries.
	t.Run("ADV_SEC33_07_CorporateArtifactMirrorLockdown", func(t *testing.T) {
		corpConfig := &config.Config{
			Version: "1",
			Mode:    config.ModeStrict,
			Network: config.NetworkConfig{
				Airgap: false,
				AllowDomains: []string{
					"artifactory.corp.internal",
					"repo.corp.internal",
				},
				UnknownDomainAction: "refused",
			},
		}

		// Corporate domain matches allowed enterprise mirror
		if !config.MatchAnyDomain(corpConfig.Network.AllowDomains, "artifactory.corp.internal") {
			t.Fatal("ADV-SEC33-07 VIOLATION: Corporate mirror artifactory.corp.internal was rejected!")
		}

		// Public package registries must be blocked under corporate policy
		publicRegistries := []string{
			"pypi.org",
			"registry.npmjs.org",
			"repo1.maven.org",
			"api.nuget.org",
			"rubygems.org",
			"crates.io",
			"docker.io",
		}
		for _, reg := range publicRegistries {
			if config.MatchAnyDomain(corpConfig.Network.AllowDomains, reg) {
				t.Fatalf("CRITICAL ADV-SEC33-07 VIOLATION: Public registry %s permitted under corporate-only profile!", reg)
			}
		}
		t.Log("PASS: ADV-SEC33-07 Corporate artifact mirror lockdown verified")
	})
}
