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
	// Ruby socket patterns (ARGUS-RB-01)
	rubySocketPatterns = []struct {
		pattern  *regexp.Regexp
		desc     string
		severity RiskLevel
	}{
		{regexp.MustCompile(`(?i)\bTCPSocket\.(new|open)\b`), "Ruby script initiates raw TCP socket connection", RiskCritical},
		{regexp.MustCompile(`(?i)\bUDPSocket\.(new|open)\b`), "Ruby script initiates raw UDP socket connection", RiskCritical},
		{regexp.MustCompile(`(?i)\bSocket\.(new|tcp|udp)\b`), "Ruby script creates low-level network socket", RiskHigh},
		{regexp.MustCompile(`(?i)\b(IPSocket|UNIXSocket|BasicSocket)\b`), "Ruby script references low-level socket API", RiskHigh},
		{regexp.MustCompile(`(?i)/dev/tcp/\d+`), "Ruby script references direct kernel TCP pseudodevice", RiskCritical},
	}

	// Ruby network download patterns (ARGUS-RB-02)
	rubyNetworkPatterns = []struct {
		pattern  *regexp.Regexp
		desc     string
		severity RiskLevel
	}{
		{regexp.MustCompile(`(?i)require\s+['"]open-uri['"]`), "Ruby script loads open-uri library for remote fetching", RiskHigh},
		{regexp.MustCompile(`(?i)\b(URI\.open|open\(URI\()`), "Ruby script initiates remote URI stream fetch", RiskHigh},
		{regexp.MustCompile(`(?i)\bNet::HTTP\b`), "Ruby script uses Net::HTTP network client", RiskHigh},
		{regexp.MustCompile(`(?i)\bNet::FTP\b`), "Ruby script uses Net::FTP network client", RiskHigh},
		{regexp.MustCompile(`(?i)\b(HTTParty|Faraday|Excon|RestClient)\b`), "Ruby script invokes third-party HTTP client library", RiskHigh},
		{regexp.MustCompile(`(?i)\b(curl|wget)\s+https?://`), "Ruby script contains explicit download command invocation", RiskHigh},
	}

	// Ruby shell execution patterns (ARGUS-RB-03)
	rubyShellPatterns = []struct {
		pattern  *regexp.Regexp
		desc     string
		severity RiskLevel
	}{
		{regexp.MustCompile(`(?i)\b(Kernel\.)?system\s*[\(\s]`), "Ruby script executes external process via system()", RiskHigh},
		{regexp.MustCompile(`(?i)\b(Kernel\.)?exec\s*[\(\s]`), "Ruby script replaces process via exec()", RiskHigh},
		{regexp.MustCompile(`(?i)\bIO\.popen\b`), "Ruby script opens external subshell pipeline via IO.popen", RiskHigh},
		{regexp.MustCompile(`(?i)\bOpen3\.(popen3|popen2|capture2|capture3)\b`), "Ruby script spawns subprocess via Open3", RiskHigh},
		{regexp.MustCompile(`(?i)\bProcess\.spawn\b`), "Ruby script spawns subprocess via Process.spawn", RiskHigh},
		{regexp.MustCompile("`[^`]+`"), "Ruby script executes shell command via backticks", RiskHigh},
		{regexp.MustCompile(`%x[\{\(\[<][^}\]\)>]+[\}\]\)>]`), "Ruby script executes shell command via %x literal", RiskHigh},
	}
)

// InspectRubyWorkspace scans the workspace for Ruby supply chain threats across
// Gemfile, *.gemspec, extconf.rb, and Rakefile.
func InspectRubyWorkspace(workspaceRoot string) []Finding {
	if workspaceRoot == "" {
		return nil
	}

	var findings []Finding

	// Discover candidate Ruby build manifests and setup scripts
	_ = filepath.WalkDir(workspaceRoot, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules" {
				return filepath.SkipDir
			}
			return nil
		}

		fileName := d.Name()
		isTarget := false

		if fileName == "Gemfile" || fileName == "Rakefile" || fileName == "rakefile" ||
			fileName == "Rakefile.rb" || fileName == "extconf.rb" ||
			strings.HasSuffix(fileName, ".gemspec") ||
			(strings.HasSuffix(fileName, ".rb") && strings.Contains(path, "/ext/")) {
			isTarget = true
		}

		if isTarget {
			fFindings, fErr := inspectRubyFile(path, workspaceRoot)
			if fErr == nil {
				findings = append(findings, fFindings...)
			}
		}
		return nil
	})

	return findings
}

func inspectRubyFile(filePath, workspaceRoot string) ([]Finding, error) {
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
			continue // Skip pure comments
		}

		// 1. Socket connections (ARGUS-RB-01)
		for _, sp := range rubySocketPatterns {
			if sp.pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      "ARGUS-RB-01",
					Severity:    sp.severity,
					Description: fmt.Sprintf("%s in %s", sp.desc, filepath.Base(filePath)),
					Target:      fmt.Sprintf("%s:%d -> %s", relFile, lineNum, line),
					Remediation: "Remove socket connection and raw network I/O from Ruby build scripts and manifests.",
				})
				break
			}
		}

		// 2. Network downloads (ARGUS-RB-02)
		for _, np := range rubyNetworkPatterns {
			if np.pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      "ARGUS-RB-02",
					Severity:    np.severity,
					Description: fmt.Sprintf("%s in %s", np.desc, filepath.Base(filePath)),
					Target:      fmt.Sprintf("%s:%d -> %s", relFile, lineNum, line),
					Remediation: "Avoid performing dynamic network downloads during gem installation or build.",
				})
				break
			}
		}

		// 3. Shell execution (ARGUS-RB-03)
		for _, shp := range rubyShellPatterns {
			if shp.pattern.MatchString(line) {
				findings = append(findings, Finding{
					RuleID:      "ARGUS-RB-03",
					Severity:    shp.severity,
					Description: fmt.Sprintf("%s in %s", shp.desc, filepath.Base(filePath)),
					Target:      fmt.Sprintf("%s:%d -> %s", relFile, lineNum, line),
					Remediation: "Remove unauthorized shell execution routines from gem installation/build routines.",
				})
				break
			}
		}
	}

	return findings, nil
}
