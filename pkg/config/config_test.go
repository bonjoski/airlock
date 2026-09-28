package config

import (
	"os"
	"path/filepath"
	"testing"
)

func TestConfig_Default(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Version != "1" {
		t.Fatalf("expected version 1, got %s", cfg.Version)
	}
	if cfg.Mode != ModeStrict {
		t.Fatalf("expected mode strict, got %s", cfg.Mode)
	}
	if !cfg.Interactive.PromptOnUnknownDomain {
		t.Fatalf("expected prompt_on_unknown_domain to be true")
	}
}

func TestConfig_LoadYAML(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "airlock.yaml")

	yamlData := `
version: "1"
mode: "strict"
network:
  airgap: false
  allow_domains:
    - "api.github.com"
    - "*.internal.corp"
env:
  allow:
    - "NODE_ENV"
  deny:
    - "SECRET_TOKEN"
vetting:
  enable: true
  strict: true
  ignored_rules:
    - "ARGUS-SQUAT-01"
`
	if err := os.WriteFile(cfgPath, []byte(yamlData), 0644); err != nil {
		t.Fatalf("failed to write test yaml: %v", err)
	}

	cfg, err := LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if len(cfg.Network.AllowDomains) != 2 {
		t.Fatalf("expected 2 allow_domains, got %d", len(cfg.Network.AllowDomains))
	}
	if cfg.Network.AllowDomains[0] != "api.github.com" {
		t.Fatalf("expected api.github.com, got %s", cfg.Network.AllowDomains[0])
	}
	if len(cfg.Env.Allow) != 1 || cfg.Env.Allow[0] != "NODE_ENV" {
		t.Fatalf("expected NODE_ENV in allow, got %v", cfg.Env.Allow)
	}
	if !cfg.Vetting.Strict {
		t.Fatalf("expected vetting.strict true")
	}
}

func TestConfig_LoadJSON(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, ".airlockrc.json")

	jsonData := `{
  "version": "1",
  "mode": "permissive",
  "network": {
    "airgap": true,
    "allow_domains": ["crates.io"]
  }
}`
	if err := os.WriteFile(cfgPath, []byte(jsonData), 0644); err != nil {
		t.Fatalf("failed to write test json: %v", err)
	}

	cfg, err := LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if cfg.Mode != ModePermissive {
		t.Fatalf("expected mode permissive, got %s", cfg.Mode)
	}
	if !cfg.Network.Airgap {
		t.Fatalf("expected airgap true")
	}
}

func TestConfig_Guardrails_StripForbiddenPaths(t *testing.T) {
	cfg := DefaultConfig()
	cfg.Filesystem.AllowRead = []string{
		"~/.ssh",
		"~/.ssh/id_rsa",
		"~/.aws/credentials",
		"/var/run/docker.sock",
		".git/hooks",
		"/shared/safe-libs",
	}
	cfg.Filesystem.AllowWrite = []string{
		"~/.ssh/authorized_keys",
		"/tmp/valid-scratch",
	}
	cfg.Env.Allow = []string{
		"SAFE_VAR",
		"LD_PRELOAD",
		"DYLD_INSERT_LIBRARIES",
	}

	issues := SanitizeAndEnforceGuardrails(cfg)

	// Check allow_read
	if len(cfg.Filesystem.AllowRead) != 1 || cfg.Filesystem.AllowRead[0] != "/shared/safe-libs" {
		t.Fatalf("expected only safe-libs in allow_read, got: %v", cfg.Filesystem.AllowRead)
	}

	// Check allow_write
	if len(cfg.Filesystem.AllowWrite) != 1 || cfg.Filesystem.AllowWrite[0] != "/tmp/valid-scratch" {
		t.Fatalf("expected only valid-scratch in allow_write, got: %v", cfg.Filesystem.AllowWrite)
	}

	// Check env allow
	if len(cfg.Env.Allow) != 1 || cfg.Env.Allow[0] != "SAFE_VAR" {
		t.Fatalf("expected only SAFE_VAR in env.allow, got: %v", cfg.Env.Allow)
	}

	if len(issues) < 5 {
		t.Fatalf("expected at least 5 guardrail issues reported, got %d", len(issues))
	}
}

func TestConfig_MatchDomain(t *testing.T) {
	cases := []struct {
		rule     string
		host     string
		expected bool
	}{
		{"registry.npmjs.org", "registry.npmjs.org", true},
		{"registry.npmjs.org", "registry.npmjs.org:443", true},
		{"registry.npmjs.org", "pypi.org", false},
		{"*.github.com", "api.github.com", true},
		{"*.github.com", "raw.githubusercontent.com", false},
		{"*.github.com", "github.com", true},
		{"*.internal.corp", "sub.internal.corp", true},
		{"*.internal.corp", "evil-internal.corp", false},
		{"pypi.org", "pypi.org", true},
	}

	for _, c := range cases {
		got := MatchDomain(c.rule, c.host)
		if got != c.expected {
			t.Errorf("MatchDomain(%q, %q) = %v; want %v", c.rule, c.host, got, c.expected)
		}
	}
}

func TestConfig_AppendAllowedDomain(t *testing.T) {
	tmpDir := t.TempDir()
	cfgPath := filepath.Join(tmpDir, "airlock.yaml")

	if err := AppendAllowedDomain(cfgPath, "api.openai.com"); err != nil {
		t.Fatalf("AppendAllowedDomain failed: %v", err)
	}

	cfg, err := LoadFromFile(cfgPath)
	if err != nil {
		t.Fatalf("LoadFromFile failed: %v", err)
	}

	if !MatchAnyDomain(cfg.Network.AllowDomains, "api.openai.com") {
		t.Fatalf("expected api.openai.com in allow_domains")
	}

	// Append same domain again (idempotent)
	if err := AppendAllowedDomain(cfgPath, "api.openai.com"); err != nil {
		t.Fatalf("AppendAllowedDomain 2 failed: %v", err)
	}

	cfg, _ = LoadFromFile(cfgPath)
	if len(cfg.Network.AllowDomains) != 1 {
		t.Fatalf("expected 1 domain, got %d", len(cfg.Network.AllowDomains))
	}
}

func TestConfig_GenerateTemplate(t *testing.T) {
	types := []string{"node", "python", "rust", "go", "general"}
	for _, typ := range types {
		tmpl := GenerateTemplate(typ)
		if len(tmpl) < 50 {
			t.Fatalf("template for %s too short", typ)
		}
	}
}
