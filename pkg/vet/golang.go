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
	// goModReplaceSingleRegex matches single-line replace directives: replace foo [v1.0.0] => bar [v1.0.0]
	goModReplaceSingleRegex = regexp.MustCompile(`(?m)^\s*replace\s+([^\s=>]+)(?:\s+v[^\s=>]+)?\s+=>\s+([^\s\n\r]+)`)
	// goModReplaceBlockLineRegex matches lines inside a replace ( ... ) block: foo [v1.0.0] => bar [v1.0.0]
	goModReplaceBlockLineRegex = regexp.MustCompile(`(?m)^\s*([^\s=>]+)(?:\s+v[^\s=>]+)?\s+=>\s+([^\s\n\r]+)`)
	// goGenerateRegex matches //go:generate or // go:generate directives
	goGenerateRegex = regexp.MustCompile(`(?m)^\s*//\s*go:generate\s+(.+)$`)
)

// InspectGoWorkspace scans the workspace for Go supply chain threats including
// suspicious go.mod replace directives and high-risk go:generate invocations.
func InspectGoWorkspace(workspaceRoot string) []Finding {
	if workspaceRoot == "" {
		return nil
	}

	var findings []Finding

	// 1. Inspect go.mod for suspicious replace directives
	goModPath := filepath.Join(workspaceRoot, "go.mod")
	if data, err := os.ReadFile(goModPath); err == nil {
		findings = append(findings, inspectGoMod(string(data), goModPath, workspaceRoot)...)
	}

	// 2. Inspect *.go source files for dangerous go:generate directives
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

		if strings.HasSuffix(d.Name(), ".go") {
			if fFindings, fErr := inspectGoSourceFile(path, workspaceRoot); fErr == nil {
				findings = append(findings, fFindings...)
			}
		}
		return nil
	})

	return findings
}

func inspectGoMod(content, filePath, workspaceRoot string) []Finding {
	var findings []Finding

	type replacement struct {
		original string
		target   string
		lineNum  int
	}

	var replacements []replacement

	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNum := 0
	inReplaceBlock := false

	for scanner.Scan() {
		lineNum++
		line := strings.TrimSpace(scanner.Text())
		if strings.HasPrefix(line, "//") {
			continue
		}

		if strings.HasPrefix(line, "replace (") {
			inReplaceBlock = true
			continue
		}
		if inReplaceBlock {
			if line == ")" {
				inReplaceBlock = false
				continue
			}
			if matches := goModReplaceBlockLineRegex.FindStringSubmatch(line); len(matches) >= 3 {
				replacements = append(replacements, replacement{
					original: matches[1],
					target:   matches[2],
					lineNum:  lineNum,
				})
			}
			continue
		}

		if matches := goModReplaceSingleRegex.FindStringSubmatch(line); len(matches) >= 3 {
			replacements = append(replacements, replacement{
				original: matches[1],
				target:   matches[2],
				lineNum:  lineNum,
			})
		}
	}

	sensitivePrefixes := []string{
		"/etc", "/root", "/var", "/tmp", "/dev", "/proc", "/sys", "/opt",
		"~", "/home", "/Users",
	}

	for _, rep := range replacements {
		target := rep.target
		cleanTarget := filepath.Clean(target)
		isSuspicious := false
		reason := ""
		severity := RiskHigh

		// Check remote URLs in replace directive
		if strings.HasPrefix(target, "http://") || strings.HasPrefix(target, "https://") ||
			strings.HasPrefix(target, "git://") || strings.HasPrefix(target, "ftp://") ||
			strings.HasPrefix(target, "ssh://") {
			isSuspicious = true
			severity = RiskCritical
			reason = fmt.Sprintf("unsupported remote protocol URI %q", target)
		}

		// Check obfuscated path sequences
		if !isSuspicious {
			if strings.Contains(target, "%2e") || strings.Contains(target, "%2f") ||
				strings.Contains(target, `\x`) || strings.Contains(target, "\x00") {
				isSuspicious = true
				severity = RiskCritical
				reason = fmt.Sprintf("obfuscated or encoded path sequence %q", target)
			}
		}

		// Check sensitive root paths
		if !isSuspicious {
			for _, prefix := range sensitivePrefixes {
				if target == prefix || strings.HasPrefix(target, prefix+"/") {
					// Check if target is outside workspace
					if workspaceRoot == "" || !strings.HasPrefix(cleanTarget, filepath.Clean(workspaceRoot)) {
						isSuspicious = true
						severity = RiskCritical
						reason = fmt.Sprintf("target points to sensitive system directory %q", target)
						break
					}
				}
			}
		}

		// Check path traversal escaping workspace
		if !isSuspicious && strings.Contains(target, "..") {
			if workspaceRoot != "" {
				absTarget := filepath.Clean(filepath.Join(workspaceRoot, target))
				rel, err := filepath.Rel(workspaceRoot, absTarget)
				if err != nil || strings.HasPrefix(rel, "..") {
					isSuspicious = true
					severity = RiskCritical
					reason = fmt.Sprintf("path traversal escapes workspace root: %q", target)
				}
			} else {
				if strings.HasPrefix(cleanTarget, "..") {
					isSuspicious = true
					severity = RiskHigh
					reason = fmt.Sprintf("relative path traversal targeting parent directories: %q", target)
				}
			}
		}

		if isSuspicious {
			relFile, _ := filepath.Rel(workspaceRoot, filePath)
			if relFile == "" {
				relFile = filePath
			}
			findings = append(findings, Finding{
				RuleID:      "ARGUS-GO-01",
				Severity:    severity,
				Description: fmt.Sprintf("go.mod contains suspicious replace directive (%s)", reason),
				Target:      fmt.Sprintf("%s:%d -> replace %s => %s", relFile, rep.lineNum, rep.original, rep.target),
				Remediation: "Remove suspicious replace directives targeting sensitive or external paths.",
			})
		}
	}

	return findings
}

func inspectGoSourceFile(filePath, workspaceRoot string) ([]Finding, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return nil, err
	}

	var findings []Finding
	scanner := bufio.NewScanner(strings.NewReader(string(data)))
	lineNum := 0

	dangerousBinaries := []string{
		"curl", "wget", "nc", "netcat", "socat",
		"bash", "sh", "zsh", "csh", "ksh",
		"python", "python3", "ruby", "perl", "php",
		"powershell", "pwsh", "cmd", "cmd.exe",
		"base64", "certutil",
	}

	for scanner.Scan() {
		lineNum++
		line := scanner.Text()
		matches := goGenerateRegex.FindStringSubmatch(line)
		if len(matches) < 2 {
			continue
		}

		cmdPayload := strings.TrimSpace(matches[1])
		cmdFields := strings.Fields(cmdPayload)
		if len(cmdFields) == 0 {
			continue
		}

		invokedBin := strings.ToLower(filepath.Base(cmdFields[0]))
		isDangerous := false

		for _, db := range dangerousBinaries {
			if invokedBin == db || strings.HasPrefix(invokedBin, db+" ") {
				isDangerous = true
				break
			}
		}

		// Also check if payload contains shell flags or pipelines
		if !isDangerous {
			lowerPayload := strings.ToLower(cmdPayload)
			if strings.Contains(lowerPayload, "curl ") ||
				strings.Contains(lowerPayload, "wget ") ||
				strings.Contains(lowerPayload, "bash -c") ||
				strings.Contains(lowerPayload, "sh -c") ||
				strings.Contains(lowerPayload, "python -c") ||
				strings.Contains(lowerPayload, "python3 -c") ||
				strings.Contains(lowerPayload, "| sh") ||
				strings.Contains(lowerPayload, "| bash") {
				isDangerous = true
			}
		}

		if isDangerous {
			relFile, _ := filepath.Rel(workspaceRoot, filePath)
			if relFile == "" {
				relFile = filePath
			}
			findings = append(findings, Finding{
				RuleID:      "ARGUS-GO-02",
				Severity:    RiskCritical,
				Description: fmt.Sprintf("Go source file contains high-risk go:generate directive invoking shell or network binary: %q", cmdPayload),
				Target:      fmt.Sprintf("%s:%d", relFile, lineNum),
				Remediation: "Remove unsafe go:generate shell or network download commands from source code.",
			})
		}
	}

	return findings, nil
}
