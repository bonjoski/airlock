package vet

import (
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/seatbelt"
)

func hasSirenRule(findings []SirenFinding, ruleID string) bool {
	for _, f := range findings {
		if f.RuleID == ruleID {
			return true
		}
	}
	return false
}

func TestSirenLint_ValidHardenedProfilesPassCleanly(t *testing.T) {
	gen := seatbelt.NewGenerator()
	cases := []struct {
		name   string
		cfg    *config.Config
		params seatbelt.Params
	}{
		{
			name: "default-proxy-hardened",
			cfg:  config.DefaultConfig(),
			params: seatbelt.Params{
				UserHome:      "/Users/devuser",
				WorkspaceRoot: "/Users/devuser/code/app",
				ScratchDir:    "/tmp/airlock-vet-test",
				ProxyPort:     18443,
			},
		},
		{
			name: "dev-agent-hardened",
			cfg: func() *config.Config {
				c, _ := config.GetBuiltinProfile(config.ProfileDevAgent)
				return c
			}(),
			params: seatbelt.Params{
				Profile:       "dev-agent",
				UserHome:      "/Users/devuser",
				WorkspaceRoot: "/Users/devuser/code/app",
				ScratchDir:    "/tmp/airlock-vet-test",
				ProxyPort:     18443,
				AntiLoopback:  true,
			},
		},
		{
			name: "airgap-hardened",
			cfg: func() *config.Config {
				c, _ := config.GetBuiltinProfile(config.ProfileAirgap)
				return c
			}(),
			params: seatbelt.Params{
				UserHome:      "/Users/devuser",
				WorkspaceRoot: "/Users/devuser/code/app",
				ScratchDir:    "/tmp/airlock-vet-test",
				Airgap:        true,
			},
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			sb, err := gen.Generate(tc.params)
			if err != nil {
				t.Fatalf("Generate failed: %v", err)
			}
			findings, err := VetProfileStrict(tc.cfg, sb)
			if err != nil {
				t.Fatalf("VetProfileStrict returned error: %v", err)
			}
			if len(findings) != 0 {
				t.Fatalf("expected 0 Siren findings for hardened profile %s, got %+v", tc.name, findings)
			}
		})
	}
}

func TestSirenLint_AdversarialCommentAndWhitespaceEvasion(t *testing.T) {
	// Crafted SBPL hiding broad (allow file-read*) and (allow default) behind comments & newlines
	evasiveSBPL := `
(version 1)
(allow
  ;; innocuous looking comment to trick naive regexes
  default)
(allow
  ; split across lines with tabs and comments
  file-read*
)
`
	findings, err := VetProfileStrict(nil, evasiveSBPL)
	if err != nil {
		t.Fatalf("unexpected parse error on valid evasive SBPL: %v", err)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-006") {
		t.Errorf("expected AIRLOCK-SIREN-006 for comment-evaded (allow default), got %+v", findings)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-001") {
		t.Errorf("expected AIRLOCK-SIREN-001 for comment-evaded broad (allow file-read*) without denies, got %+v", findings)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-002") {
		t.Errorf("expected AIRLOCK-SIREN-002 for missing ~/.ssh, ~/.aws, docker.sock denies, got %+v", findings)
	}
}

func TestSirenLint_AdversarialLastMatchWinsOverride(t *testing.T) {
	// Places broad (allow file-read*) AFTER credential denies so Seatbelt's last-match-wins
	// semantics silently nullify the earlier denies!
	reorderedSBPL := `
(version 1)
(deny default)
(deny file-read* file-write*
  (subpath "/Users/dev/.ssh")
  (subpath "/Users/dev/.aws")
  (literal "/var/run/docker.sock"))
;; Attacker appends broad allow AFTER denies:
(allow
  ; bypass!
  file-read*)
(deny network*)
`
	findings, err := VetProfileStrict(config.DefaultConfig(), reorderedSBPL)
	if err != nil {
		t.Fatalf("unexpected parse error: %v", err)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-001") {
		t.Fatalf("expected AIRLOCK-SIREN-001 when broad (allow file-read*) overrides earlier credential denies, got %+v", findings)
	}
}

func TestSirenLint_AdversarialMissingIndividualCredentialDenies(t *testing.T) {
	// Has ~/.ssh and ~/.aws denies, but omits /var/run/docker.sock
	missingDockerSock := `
(version 1)
(deny default)
(allow file-read*)
(deny file-read* file-write*
  (subpath "/Users/dev/.ssh")
  (subpath "/Users/dev/.aws"))
(deny network*)
`
	findings, err := VetProfileStrict(config.DefaultConfig(), missingDockerSock)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-002") {
		t.Fatalf("expected AIRLOCK-SIREN-002 for missing docker.sock deny, got %+v", findings)
	}
	foundDocker := false
	for _, f := range findings {
		if strings.Contains(f.Summary, "docker.sock") {
			foundDocker = true
		}
	}
	if !foundDocker {
		t.Errorf("expected finding summary mentioning docker.sock, got %+v", findings)
	}
}

func TestSirenLint_AdversarialWildcardNetworkEgress(t *testing.T) {
	wildcardSBPL := `
(version 1)
(deny default)
(allow file-read*)
(deny file-read* file-write*
  (subpath "/Users/dev/.ssh")
  (subpath "/Users/dev/.aws")
  (literal "/var/run/docker.sock"))
(allow network-outbound (to tcp "*:443"))
`
	findings, err := VetProfileStrict(config.DefaultConfig(), wildcardSBPL)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-003") {
		t.Fatalf("expected AIRLOCK-SIREN-003 for wildcard egress without allowlist, got %+v", findings)
	}

	// Config-level wildcard & cloud IMDS egress rules
	badCfg := config.DefaultConfig()
	badCfg.Network.AllowDomains = []string{"*", "*.com", "169.254.169.254", "10.0.0.1"}
	cfgFindings, err := VetProfileStrict(badCfg, "")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasSirenRule(cfgFindings, "AIRLOCK-SIREN-003") {
		t.Fatalf("expected AIRLOCK-SIREN-003 for wildcard/IMDS config allow_domains, got %+v", cfgFindings)
	}
}

func TestSirenLint_AdversarialRelativePathAndLinkerSmuggling(t *testing.T) {
	badCfg := config.DefaultConfig()
	badCfg.Env.Allow = []string{"LD_PRELOAD", "PYTHONPATH", "PATH=./bin:/usr/bin"}

	findings, err := VetProfileStrict(badCfg, "--setenv PATH .:/usr/bin:/bin")
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !hasSirenRule(findings, "AIRLOCK-SIREN-004") {
		t.Fatalf("expected AIRLOCK-SIREN-004 for relative PATH and linker vars, got %+v", findings)
	}
}

func TestSirenLint_AdversarialDisabledSeccompAndFailOpenDegraded(t *testing.T) {
	degradedProfile := `
landlock:
  allow_fs=/
  seccomp: disabled
  io_uring=allow
  x32_abi=allow
  --allow-degraded-local
`
	badCfg := config.DefaultConfig()
	badCfg.Mode = config.ModePermissive
	badCfg.Vetting.IgnoredRules = []string{"ARGUS-CMD-01"}

	findings, err := VetProfileStrict(badCfg, degradedProfile)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{"AIRLOCK-SIREN-001", "AIRLOCK-SIREN-005", "AIRLOCK-SIREN-006"} {
		if !hasSirenRule(findings, want) {
			t.Errorf("expected finding %s, got %+v", want, findings)
		}
	}
}

func TestSirenLint_AdversarialMalformedSBPLFailsClosed(t *testing.T) {
	malformed := `(version 1) (deny default (allow file-read*`
	_, err := VetProfileStrict(nil, malformed)
	if err == nil {
		t.Fatal("expected fail-closed error on malformed/unbalanced SBPL, got nil")
	}
}
