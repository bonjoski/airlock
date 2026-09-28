package vet

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"strings"
)

var (
	shellExploitPatterns = []struct {
		pattern  *regexp.Regexp
		ruleID   string
		severity RiskLevel
		desc     string
	}{
		{
			pattern:  regexp.MustCompile(`(?i)\bbase64\s+[^|]*(-[a-zA-Z]*[dD][a-zA-Z]*|--decode)[^|]*\|\s*(/bin/|/usr/bin/)?(ba|z)?sh\b`),
			ruleID:   "ARGUS-SHELL-01",
			severity: RiskCritical,
			desc:     "Detected obfuscated base64 payload piped directly into shell interpreter",
		},
		{
			pattern:  regexp.MustCompile(`(?i)\b(echo|printf)\s+[^|]+\|\s*(/bin/|/usr/bin/)?(ba|z)?sh\b`),
			ruleID:   "ARGUS-SHELL-02",
			severity: RiskCritical,
			desc:     "Detected dynamic command stream (echo/printf) piped directly into shell interpreter",
		},
		{
			pattern:  regexp.MustCompile(`(?i)\bwget\s+[^|]*(-O\s*-\s*|-qO-\s*|--output-document\s*=\s*-\s*)[^|]*\|\s*(/bin/|/usr/bin/)?(ba|z)?sh\b`),
			ruleID:   "ARGUS-SHELL-03",
			severity: RiskCritical,
			desc:     "Detected remote wget download stream piped directly into shell interpreter",
		},
		{
			pattern:  regexp.MustCompile(`(?i)\b(curl|wget)\s+[^|]+\|\s*(/usr/bin/|/usr/local/bin/)?python[23]?\b`),
			ruleID:   "ARGUS-SHELL-04",
			severity: RiskCritical,
			desc:     "Detected remote download stream piped directly into Python interpreter",
		},
		{
			pattern:  regexp.MustCompile(`(?i)\b(powershell|pwsh)(\.exe)?\s+.*(-e|-enc|-encodedcommand)\b`),
			ruleID:   "ARGUS-SHELL-05",
			severity: RiskCritical,
			desc:     "Detected PowerShell execution with encoded command payload",
		},
	}
)

// InspectShellCommand analyzes command line arguments for obfuscated pipelines and shell exploits.
func InspectShellCommand(cmdArgs []string) []Finding {
	if len(cmdArgs) == 0 {
		return nil
	}

	fullCmd := strings.Join(cmdArgs, " ")
	var findings []Finding

	for _, p := range shellExploitPatterns {
		if p.pattern.MatchString(fullCmd) {
			findings = append(findings, Finding{
				RuleID:      p.ruleID,
				Severity:    p.severity,
				Description: p.desc,
				Target:      fullCmd,
				Remediation: "Do not execute obfuscated commands or direct remote pipeline interpreters.",
			})
		}
	}

	return findings
}

// InspectShellWorkspace scans workspace shell scripts (*.sh, *.bash) for obfuscated pipeline exploits.
func InspectShellWorkspace(workspaceRoot string) []Finding {
	if workspaceRoot == "" {
		return nil
	}

	var findings []Finding

	_ = filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "node_modules" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}

		name := d.Name()
		if strings.HasSuffix(name, ".sh") || strings.HasSuffix(name, ".bash") || strings.HasSuffix(name, ".zsh") {
			if fFindings, fErr := inspectShellFile(path, workspaceRoot); fErr == nil {
				findings = append(findings, fFindings...)
			}
		}
		return nil
	})

	return findings
}

func inspectShellFile(filePath, workspaceRoot string) ([]Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	relFile, _ := filepath.Rel(workspaceRoot, filePath)
	if relFile == "" {
		relFile = filePath
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "#") {
			continue
		}

		for _, p := range shellExploitPatterns {
			if p.pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      p.ruleID,
					Severity:    p.severity,
					Description: fmt.Sprintf("%s in %s", p.desc, filepath.Base(filePath)),
					Target:      fmt.Sprintf("%s:%d -> %s", relFile, lineNum, line),
					Remediation: "Remove unsafe shell pipeline execution or encoded payloads.",
				})
			}
		}
	}

	return findings, nil
}
