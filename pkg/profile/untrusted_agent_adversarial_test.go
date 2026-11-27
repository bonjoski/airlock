package profile

import (
	"fmt"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/landlock"
	"github.com/bonjoski/airlock/pkg/seatbelt"
	"github.com/bonjoski/airlock/pkg/vet"
)

func envToMap(env []string) map[string]string {
	m := make(map[string]string, len(env))
	for _, kv := range env {
		if idx := strings.Index(kv, "="); idx > 0 {
			m[kv[:idx]] = kv[idx+1:]
		}
	}
	return m
}

func TestUntrustedAgent_AdversarialEnvScrubAndPathShadowing(t *testing.T) {
	// Construct synthetic fixtures via concatenation so push protection never triggers
	fakeAWSKey := "AKIA" + "IOSFODNN7EXAMPLE"
	fakeAWSSecret := "wJalrXUtnFEMI/" + "K7MDENG/bPxRfiCYEXAMPLEKEY"
	fakeAnthropic := "sk-" + "ant-api03-synthetic000000000000000000000"
	fakeOpenAI := "sk-" + "proj-synthetic000000000000000000000"
	fakeGitHub := "ghp_" + "synthetic000000000000000000000000000000"

	hostEnv := []string{
		"PATH=.:./bin:/Users/dev/.local/bin:/tmp/evil:/usr/bin:/bin",
		"TERM=xterm-256color",
		"LANG=en_US.UTF-8",
		"AWS_ACCESS_KEY_ID=" + fakeAWSKey,
		"AWS_SECRET_ACCESS_KEY=" + fakeAWSSecret,
		"ANTHROPIC_API_KEY=" + fakeAnthropic,
		"OPENAI_API_KEY=" + fakeOpenAI,
		"GEMINI_API_KEY=AIza" + "SySynthetic00000000000000000",
		"GOOGLE_API_KEY=AIza" + "SySynthetic11111111111111111",
		"GITHUB_TOKEN=" + fakeGitHub,
		"GH_TOKEN=" + fakeGitHub,
		"AZURE_CLIENT_SECRET=synthetic-azure",
		"GCP_PROJECT_KEY=synthetic-gcp",
		"STRIPE_SECRET_KEY=sk_" + "test_synthetic000000000000",
		"SLACK_BOT_TOKEN=xoxb-" + "synthetic-0000000000",
		"SSH_AUTH_SOCK=/private/tmp/com.apple.launchd.abc/Listeners",
		"LD_PRELOAD=/tmp/evil.so",
		"DYLD_INSERT_LIBRARIES=/tmp/evil.dylib",
		"PYTHONPATH=/tmp/evil_py",
		"NODE_OPTIONS=--require /tmp/evil.js",
		"GIT_CONFIG_PARAMETERS='core.sshCommand=evil'",
	}

	cleaned, err := BuildUntrustedAgentEnv(hostEnv, UntrustedAgentConfig{
		WorkDir: "/tmp/worktree-1",
	})
	if err != nil {
		t.Fatalf("BuildUntrustedAgentEnv failed: %v", err)
	}

	envMap := envToMap(cleaned)

	// 1. Verify immutable PATH replaces trojan/writable directories
	wantPath := strings.Join(UntrustedAgentDefaultPATH, ":")
	if envMap["PATH"] != wantPath {
		t.Fatalf("PATH shadowing not neutralized: got %q, want %q", envMap["PATH"], wantPath)
	}

	// 2. Verify every scrubbed secret and injection vector is absent
	mustBeAbsent := []string{
		"AWS_ACCESS_KEY_ID",
		"AWS_SECRET_ACCESS_KEY",
		"ANTHROPIC_API_KEY",
		"OPENAI_API_KEY",
		"GEMINI_API_KEY",
		"GOOGLE_API_KEY",
		"GITHUB_TOKEN",
		"GH_TOKEN",
		"AZURE_CLIENT_SECRET",
		"GCP_PROJECT_KEY",
		"STRIPE_SECRET_KEY",
		"SLACK_BOT_TOKEN",
		"SSH_AUTH_SOCK",
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
		"PYTHONPATH",
		"NODE_OPTIONS",
		"GIT_CONFIG_PARAMETERS",
	}
	for _, k := range mustBeAbsent {
		if v, exists := envMap[k]; exists {
			t.Errorf("credential/injection env %s leaked into untrusted-agent env (val=%q)", k, v)
		}
	}

	// 3. Verify safe baseline vars remain
	if envMap["TERM"] != "xterm-256color" {
		t.Errorf("expected TERM to be preserved, got %q", envMap["TERM"])
	}
}

func TestUntrustedAgent_AdversarialKeylessProxyPlaceholders(t *testing.T) {
	env1, err := BuildUntrustedAgentEnv([]string{"ANTHROPIC_API_KEY=" + "sk-" + "ant-real-key"}, UntrustedAgentConfig{
		KeylessProxyAddr:   "127.0.0.1:8443",
		AllowedPlaceholder: []string{"ANTHROPIC_API_KEY"},
	})
	if err != nil {
		t.Fatalf("BuildUntrustedAgentEnv with valid loopback keyless proxy failed: %v", err)
	}
	env2, err := BuildUntrustedAgentEnv(nil, UntrustedAgentConfig{
		KeylessProxyAddr:   "[::1]:8443",
		AllowedPlaceholder: []string{"ANTHROPIC_API_KEY"},
	})
	if err != nil {
		t.Fatalf("BuildUntrustedAgentEnv with valid IPv6 loopback keyless proxy failed: %v", err)
	}

	m1 := envToMap(env1)
	m2 := envToMap(env2)

	if !strings.HasPrefix(m1["ANTHROPIC_API_KEY"], "locksmith_placeholder_") || len(m1["ANTHROPIC_API_KEY"]) != len("locksmith_placeholder_")+32 {
		t.Fatalf("expected 32-hex CSPRNG placeholder token, got %q", m1["ANTHROPIC_API_KEY"])
	}
	if m1["ANTHROPIC_API_KEY"] == m2["ANTHROPIC_API_KEY"] {
		t.Fatal("placeholder tokens must be unique per session")
	}
	if m1["HTTPS_PROXY"] != "http://127.0.0.1:8443" {
		t.Errorf("expected HTTPS_PROXY=http://127.0.0.1:8443, got %q", m1["HTTPS_PROXY"])
	}
	if m2["HTTPS_PROXY"] != "http://[::1]:8443" {
		t.Errorf("expected HTTPS_PROXY=http://[::1]:8443, got %q", m2["HTTPS_PROXY"])
	}
}

func TestUntrustedAgent_AdversarialValidateEgressAllowlist(t *testing.T) {
	// Valid declared API hosts
	if err := ValidateEgressAllowlist([]string{"api.anthropic.com", "api.openai.com", "generativelanguage.googleapis.com:443"}); err != nil {
		t.Fatalf("expected valid API hosts to pass, got %v", err)
	}

	// Hostile / forbidden inputs that MUST fail closed
	forbidden := []string{
		"",
		"   ",
		"*",
		"*.anthropic.com",
		"*.com",
		"api.anthropic.com;id",
		"api.anthropic.com|sh",
		"api.anthropic.com$(whoami)",
		"api.anthropic.com`id`",
		"api.anthropic.com\n127.0.0.1",
		"https://api.anthropic.com",
		"api.anthropic.com/v1/messages",
		"user@api.anthropic.com",
		"localhost",
		"sub.localhost",
		"printer.local",
		"metadata.google.internal",
		"127.0.0.1",
		"127.0.0.1:8080",
		"::1",
		"[::1]:8443",
		"10.0.0.1",
		"172.16.0.1",
		"192.168.1.1",
		"100.64.0.1",
		"169.254.169.254",
		"169.254.169.254:80",
		"[::ffff:169.254.169.254]",
		"[fe80::1]",
		"0.0.0.0",
		"2852039166", // Decimal-encoded 169.254.169.254
		"0xa9fea9fe", // Hex-encoded 169.254.169.254
		"0177.0.0.1", // Octal-encoded 127.0.0.1
		"singlelabel",
	}

	for _, bad := range forbidden {
		if err := ValidateEgressAllowlist([]string{bad}); err == nil {
			t.Errorf("ValidateEgressAllowlist accepted forbidden host %q (must fail closed)", bad)
		}
	}
}

func TestUntrustedAgent_AdversarialValidateKeylessProxyAddr(t *testing.T) {
	for _, okAddr := range []string{"127.0.0.1:8443", "[::1]:8443"} {
		ap, err := ValidateKeylessProxyAddr(okAddr)
		if err != nil {
			t.Fatalf("expected valid loopback proxy %q to pass, got %v", okAddr, err)
		}
		if ap.Port() != 8443 {
			t.Errorf("expected port 8443, got %d", ap.Port())
		}
	}

	forbidden := []string{
		"",
		"   ",
		"localhost:8443",
		"http://127.0.0.1:8443",
		"0.0.0.0:8443",
		"[::]:8443",
		"127.0.0.2:8443",
		"[::ffff:127.0.0.1]:8443",
		"10.0.0.5:8443",
		"192.168.1.50:8443",
		"169.254.169.254:80",
		"8.8.8.8:443",
		"127.0.0.1:0",
		"127.0.0.1",
		"127.0.0.1:8443;rm -rf /",
		"127.0.0.1:8443\n(allow default)",
	}
	for _, bad := range forbidden {
		if _, err := ValidateKeylessProxyAddr(bad); err == nil {
			t.Errorf("ValidateKeylessProxyAddr accepted non-loopback/malformed addr %q (must fail closed)", bad)
		}
	}
}

func TestUntrustedAgent_SeatbeltPersistenceAndWANDeny(t *testing.T) {
	sb, err := GenerateUntrustedAgentSeatbelt(seatbelt.Params{
		UserHome:      "/Users/devuser",
		WorkspaceRoot: "/Users/devuser/code/untrusted",
		ScratchDir:    "/tmp/airlock-ua-scratch",
		AllowDirectNet: true, // Attempted direct net MUST be overridden to WAN=DENY
	}, UntrustedAgentConfig{
		WorkDir: "/Users/devuser/code/untrusted",
	})
	if err != nil {
		t.Fatalf("GenerateUntrustedAgentSeatbelt failed: %v", err)
	}

	// Default WAN=DENY when no egress or proxy configured
	if !strings.Contains(sb, "(deny network*)") {
		t.Error("expected (deny network*) in WAN=DENY mode")
	}
	if strings.Contains(sb, `*:443`) {
		t.Error("untrusted-agent must NEVER allow wildcard *:443 direct egress")
	}

	// Explicit SSH, persistence, shell rc, LaunchAgents, and /etc/cron* denials
	requiredDenies := []string{
		"/Users/devuser/.ssh",
		"/Users/devuser/.ssh/authorized_keys",
		"/Users/devuser/.bashrc",
		"/Users/devuser/.zshrc",
		"/Users/devuser/.profile",
		"/Users/devuser/Library/LaunchAgents",
		`^/etc/cron.*`,
		"/var/run/docker.sock",
	}
	for _, req := range requiredDenies {
		if !strings.Contains(sb, req) {
			t.Errorf("Seatbelt profile missing required deny for %q", req)
		}
	}

	// Cross-check: compiled untrusted-agent Seatbelt profile must PASS Siren strict lint with 0 findings!
	uaProfileCfg, err := config.GetBuiltinProfile(config.ProfileUntrustedAgent)
	if err != nil {
		t.Fatalf("GetBuiltinProfile(untrusted-agent): %v", err)
	}
	findings, err := vet.VetProfileStrict(uaProfileCfg, sb)
	if err != nil {
		t.Fatalf("VetProfileStrict returned error on untrusted-agent SBPL: %v", err)
	}
	if len(findings) != 0 {
		t.Fatalf("expected 0 Siren findings on untrusted-agent SBPL, got %+v", findings)
	}
}

func TestUntrustedAgent_LandlockAndBwrapPersistenceLock(t *testing.T) {
	rs := BuildUntrustedAgentLandlock(landlock.Config{
		WorkspaceRoot:   "/home/dev/worktree",
		ScratchDir:      "/tmp/airlock-ua-1",
		UserHome:        "/home/dev",
		ExtraAllowRead:  []string{"/home/dev/.ssh", "/etc/cron.d", "/home/dev/.zshrc"},
		ExtraAllowWrite: []string{"/home/dev/.ssh/authorized_keys", "/home/dev/Library/LaunchAgents"},
	}, UntrustedAgentConfig{WorkDir: "/home/dev/worktree"})

	for _, r := range rs.Rules {
		if strings.Contains(r.Path, ".ssh") || strings.Contains(r.Path, ".local/bin") ||
			strings.Contains(r.Path, ".zshrc") || strings.Contains(r.Path, "cron") ||
			strings.Contains(r.Path, "LaunchAgents") {
			t.Errorf("Landlock ruleset must never allow %q", r.Path)
		}
	}

	bwrapArgs := AugmentBwrapArgsForUntrustedAgent([]string{"--unshare-user"}, "/home/dev", "/tmp/mask", UntrustedAgentConfig{})
	joined := strings.Join(bwrapArgs, " ")
	for _, want := range []string{
		"--cap-drop ALL",
		"--unshare-net",
		"/home/dev/.ssh/authorized_keys",
		"/home/dev/.bashrc",
		"/home/dev/.zshrc",
		"/home/dev/.profile",
		"/home/dev/Library/LaunchAgents",
		"/etc/crontab",
		"/etc/cron.d",
		"--setenv PATH /usr/bin:/bin:/opt/homebrew/bin",
		"--unsetenv SSH_AUTH_SOCK",
		"--unsetenv LD_PRELOAD",
	} {
		if !strings.Contains(joined, want) {
			t.Errorf("bwrap args missing %q (got: %s)", want, joined)
		}
	}
}

func TestUntrustedAgent_ConcurrencyN8Worktrees(t *testing.T) {
	const workers = 8
	var wg sync.WaitGroup
	errs := make(chan error, workers)
	tokens := make(chan string, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func(id int) {
			defer wg.Done()
			wt := filepath.Join(t.TempDir(), fmt.Sprintf("wt-%d", id))
			cfg := UntrustedAgentConfig{
				WorkDir:            wt,
				AllowEgressHosts:   []string{"api.anthropic.com"},
				KeylessProxyAddr:   fmt.Sprintf("127.0.0.1:%d", 18440+id),
				AllowedPlaceholder: []string{"ANTHROPIC_API_KEY"},
			}

			env, err := BuildUntrustedAgentEnv([]string{
				"PATH=./bin:/usr/bin",
				"AWS_SECRET_ACCESS_KEY=" + "synthetic-secret-" + fmt.Sprint(id),
				"LD_PRELOAD=/tmp/bad.so",
			}, cfg)
			if err != nil {
				errs <- fmt.Errorf("worker %d env: %w", id, err)
				return
			}
			em := envToMap(env)
			if _, leaked := em["AWS_SECRET_ACCESS_KEY"]; leaked {
				errs <- fmt.Errorf("worker %d leaked AWS secret", id)
				return
			}
			tokens <- em["ANTHROPIC_API_KEY"]

			sb, err := GenerateUntrustedAgentSeatbelt(seatbelt.Params{
				UserHome:      "/Users/devuser",
				WorkspaceRoot: wt,
				ScratchDir:    filepath.Join(wt, ".scratch"),
			}, cfg)
			if err != nil {
				errs <- fmt.Errorf("worker %d seatbelt: %w", id, err)
				return
			}
			if !strings.Contains(sb, fmt.Sprintf("localhost:%d", 18440+id)) {
				errs <- fmt.Errorf("worker %d seatbelt missing dedicated loopback port", id)
				return
			}

			rs := BuildUntrustedAgentLandlock(landlock.Config{
				WorkspaceRoot: wt,
				ScratchDir:    filepath.Join(wt, ".scratch"),
				UserHome:      "/home/devuser",
			}, cfg)
			if rs == nil || rs.WorkspaceRoot != wt {
				errs <- fmt.Errorf("worker %d invalid landlock ruleset", id)
				return
			}

			bwrap := AugmentBwrapArgsForUntrustedAgent([]string{"--unshare-user"}, "/home/devuser", "/tmp/mask", cfg)
			if len(bwrap) == 0 {
				errs <- fmt.Errorf("worker %d empty bwrap args", id)
				return
			}
		}(i)
	}

	wg.Wait()
	close(errs)
	close(tokens)

	for err := range errs {
		t.Fatal(err)
	}

	seen := make(map[string]bool, workers)
	for tok := range tokens {
		if !strings.HasPrefix(tok, "locksmith_placeholder_") {
			t.Fatalf("invalid placeholder token: %q", tok)
		}
		if seen[tok] {
			t.Fatalf("duplicate placeholder token across parallel workers: %q", tok)
		}
		seen[tok] = true
	}
	if len(seen) != workers {
		t.Fatalf("expected %d unique placeholder tokens, got %d", workers, len(seen))
	}
}
