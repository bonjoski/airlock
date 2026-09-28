// Package vet provides pre-execution static analysis and heuristic inspection
// for packages, manifests, and command invocations prior to sandbox entry (Argus / vetpkg handoff).
package vet

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
)

// RiskLevel categorizes the severity of detected threat indicators.
type RiskLevel string

const (
	RiskNone     RiskLevel = "NONE"
	RiskLow      RiskLevel = "LOW"
	RiskMedium   RiskLevel = "MEDIUM"
	RiskHigh     RiskLevel = "HIGH"
	RiskCritical RiskLevel = "CRITICAL"
)

// Finding represents a single security issue or suspicious pattern detected during pre-execution analysis.
type Finding struct {
	RuleID      string    `json:"rule_id"`
	Severity    RiskLevel `json:"severity"`
	Description string    `json:"description"`
	Target      string    `json:"target,omitempty"`
	Remediation string    `json:"remediation,omitempty"`
}

// Report details the outcome of pre-execution static analysis inspection.
type Report struct {
	MaxRisk        RiskLevel `json:"max_risk"`
	Findings       []Finding `json:"findings"`
	BlockExecution bool      `json:"block_execution"`
	DurationMs     int64     `json:"duration_ms"`
}

// Inspector defines the interface for pre-execution package and command verification.
type Inspector interface {
	Inspect(ctx context.Context, cmdArgs []string, workspaceRoot string) (*Report, error)
}

// Config holds settings for static analysis inspection.
type Config struct {
	StrictMode   bool         // If true, High and Critical risks block execution automatically
	ExternalTool string       // Optional path to external vetpkg/argus binary
	IgnoredRules []string     // Rule IDs to ignore/suppress
	Logger       audit.Logger // Audit telemetry logger
}

// Engine implements heuristic analysis and external toolchain handoff.
type Engine struct {
	config Config
}

// NewEngine creates a new static analysis inspection engine.
func NewEngine(cfg Config) *Engine {
	if cfg.Logger == nil {
		cfg.Logger = &audit.NopLogger{}
	}
	return &Engine{config: cfg}
}

// Inspect runs heuristic checks and external vetpkg analyzers against the target command and workspace.
func (e *Engine) Inspect(ctx context.Context, cmdArgs []string, workspaceRoot string) (*Report, error) {
	start := time.Now()
	report := &Report{
		MaxRisk: RiskNone,
	}

	if len(cmdArgs) == 0 && workspaceRoot == "" {
		report.DurationMs = time.Since(start).Milliseconds()
		return report, nil
	}

	// 1. Heuristic Command Line Checks (Pipes, Flags, Typosquatting)
	if len(cmdArgs) > 0 {
		e.inspectCommandArgs(cmdArgs, report)
	}

	// 2. Workspace Manifest Analysis (package.json, setup.py, pyproject.toml, build.rs, Cargo.toml, Go, Ruby, Shell)
	if workspaceRoot != "" {
		e.inspectWorkspaceManifests(workspaceRoot, report)
	}

	// 3. External vetpkg / argus Tool Handoff
	if e.config.ExternalTool != "" || hasExecutableOnPath("vetpkg") {
		toolPath := e.config.ExternalTool
		if toolPath == "" {
			toolPath = "vetpkg"
		}
		_ = e.runExternalTool(ctx, toolPath, cmdArgs, workspaceRoot, report)
	}

	// Compute MaxRisk and Block Decision
	e.evaluateRiskAndPolicy(report)
	report.DurationMs = time.Since(start).Milliseconds()

	// Telemetry: Log security violations if findings are detected
	for _, f := range report.Findings {
		if f.Severity == RiskHigh || f.Severity == RiskCritical {
			_ = e.config.Logger.LogSecurity(audit.SecurityRecord{
				Category: "static_analysis_finding",
				Details:  fmt.Sprintf("[%s] %s: %s (%s)", f.Severity, f.RuleID, f.Description, f.Target),
			})
		}
	}

	return report, nil
}

func (e *Engine) inspectCommandArgs(cmdArgs []string, report *Report) {
	fullCmd := strings.Join(cmdArgs, " ")

	// Check for raw reverse shells or pipe-to-interpreter
	suspiciousPipes := []struct {
		pattern  string
		ruleID   string
		severity RiskLevel
		desc     string
	}{
		{`curl\s+.*\|\s*(ba)?sh`, "ARGUS-CMD-01", RiskCritical, "Detected pipe from curl to shell interpreter"},
		{`wget\s+.*\|\s*(ba)?sh`, "ARGUS-CMD-02", RiskCritical, "Detected pipe from wget to shell interpreter"},
		{`nc\s+(-e|-c)\s+`, "ARGUS-CMD-03", RiskCritical, "Detected netcat reverse shell flag execution"},
		{`--ignore-scripts=false`, "ARGUS-CMD-04", RiskMedium, "Explicit override enabling lifecycle install scripts"},
		{`--unsafe-perm`, "ARGUS-CMD-05", RiskHigh, "Package manager invoked with root privilege drop disabled"},
		{`--extra-index-url\s+http://`, "ARGUS-CMD-06", RiskHigh, "Insecure unencrypted HTTP package index configured"},
	}

	for _, check := range suspiciousPipes {
		matched, _ := regexp.MatchString(check.pattern, fullCmd)
		if matched {
			report.Findings = append(report.Findings, Finding{
				RuleID:      check.ruleID,
				Severity:    check.severity,
				Description: check.desc,
				Target:      fullCmd,
				Remediation: "Remove unsafe command flags or unvetted remote pipe execution.",
			})
		}
	}

	// Typosquatting inspection on CLI arguments
	packages := ExtractPackageNames(cmdArgs)
	for _, pkg := range packages {
		isMalicious, desc, isSquat, popularTarget := CheckTyposquatting(pkg)
		if isMalicious {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-SQUAT-02",
				Severity:    RiskCritical,
				Description: fmt.Sprintf("Command targets known malicious/backdoored package %q: %s", pkg, desc),
				Target:      pkg,
				Remediation: "Abort installation immediately. Do not execute or download this package.",
			})
		} else if isSquat {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-SQUAT-01",
				Severity:    RiskHigh,
				Description: fmt.Sprintf("Potential typosquat package %q closely resembles popular library %q", pkg, popularTarget),
				Target:      pkg,
				Remediation: fmt.Sprintf("Verify spelling. Did you intend to install %q instead?", popularTarget),
			})
		}
	}

	// Obfuscated pipeline and shell exploit checks
	report.Findings = append(report.Findings, InspectShellCommand(cmdArgs)...)
}

func (e *Engine) inspectWorkspaceManifests(workspaceRoot string, report *Report) {
	// 1. Inspect package.json for dangerous lifecycle scripts & typosquats
	pkgJSONPath := filepath.Join(workspaceRoot, "package.json")
	if data, err := os.ReadFile(pkgJSONPath); err == nil {
		var manifest struct {
			Name            string            `json:"name"`
			Scripts         map[string]string `json:"scripts"`
			Dependencies    map[string]string `json:"dependencies"`
			DevDependencies map[string]string `json:"devDependencies"`
		}
		if err := json.Unmarshal(data, &manifest); err == nil {
			lifecycleHooks := []string{"preinstall", "install", "postinstall", "prepublish", "prepublishOnly"}
			obfuscationPatterns := []string{"base64", "eval(", "curl", "wget", "socket", "/dev/tcp"}
			dangerousShellCmds := []string{"curl ", "wget ", "nc -", "bash -i", "sh -i", "python -c", "powershell", "certutil"}

			for _, hook := range lifecycleHooks {
				script, exists := manifest.Scripts[hook]
				if !exists {
					continue
				}

				scriptLower := strings.ToLower(script)
				for _, pattern := range obfuscationPatterns {
					if strings.Contains(scriptLower, pattern) {
						report.Findings = append(report.Findings, Finding{
							RuleID:      "ARGUS-HOOK-01",
							Severity:    RiskHigh,
							Description: fmt.Sprintf("Suspicious lifecycle hook %q contains high-risk pattern %q", hook, pattern),
							Target:      fmt.Sprintf("%s: %s", hook, script),
							Remediation: "Inspect package lifecycle script prior to installation.",
						})
						break
					}
				}

				for _, cmd := range dangerousShellCmds {
					if strings.Contains(scriptLower, cmd) {
						report.Findings = append(report.Findings, Finding{
							RuleID:      "ARGUS-HOOK-02",
							Severity:    RiskHigh,
							Description: fmt.Sprintf("Lifecycle hook %q executes dangerous shell download/reverse-shell command: %q", hook, cmd),
							Target:      fmt.Sprintf("%s: %s", hook, script),
							Remediation: "Remove unauthorized network access or shell execution from lifecycle scripts.",
						})
						break
					}
				}
			}

			// Check manifest dependencies for typosquatting
			allDeps := make(map[string]string)
			for k, v := range manifest.Dependencies {
				allDeps[k] = v
			}
			for k, v := range manifest.DevDependencies {
				allDeps[k] = v
			}

			for dep := range allDeps {
				isMalicious, desc, isSquat, popularTarget := CheckTyposquatting(dep)
				if isMalicious {
					report.Findings = append(report.Findings, Finding{
						RuleID:      "ARGUS-SQUAT-02",
						Severity:    RiskCritical,
						Description: fmt.Sprintf("package.json references known malicious package %q: %s", dep, desc),
						Target:      fmt.Sprintf("package.json -> %s", dep),
						Remediation: "Remove dependency immediately.",
					})
				} else if isSquat {
					report.Findings = append(report.Findings, Finding{
						RuleID:      "ARGUS-SQUAT-01",
						Severity:    RiskHigh,
						Description: fmt.Sprintf("package.json dependency %q may be a typosquat targeting %q", dep, popularTarget),
						Target:      fmt.Sprintf("package.json -> %s", dep),
						Remediation: fmt.Sprintf("Confirm if dependency was intended to be %q.", popularTarget),
					})
				}
			}
		}
	}

	// 2. Inspect setup.py for network calls and dynamic code execution
	setupPyPath := filepath.Join(workspaceRoot, "setup.py")
	if data, err := os.ReadFile(setupPyPath); err == nil {
		content := string(data)
		if strings.Contains(content, "urllib.request") || strings.Contains(content, "requests.get") || strings.Contains(content, "requests.post") || strings.Contains(content, "http.client") {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-PY-01",
				Severity:    RiskHigh,
				Description: "setup.py contains pre-execution network fetching routines",
				Target:      setupPyPath,
				Remediation: "Remove network calls from setup.py installer routines.",
			})
		}

		if strings.Contains(content, "exec(b64decode") || strings.Contains(content, "eval(compile") || strings.Contains(content, "__import__('os').system") || strings.Contains(content, "/dev/tcp/") {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-PY-02",
				Severity:    RiskCritical,
				Description: "setup.py contains obfuscated execution, base64 payload, or reverse shell syntax",
				Target:      setupPyPath,
				Remediation: "Inspect and remove obfuscated code evaluation from setup.py.",
			})
		}
	}

	// 3. Inspect pyproject.toml
	pyprojectPath := filepath.Join(workspaceRoot, "pyproject.toml")
	if data, err := os.ReadFile(pyprojectPath); err == nil {
		content := string(data)
		if strings.Contains(content, "curl ") || strings.Contains(content, "wget ") || strings.Contains(content, "http://") {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-PY-03",
				Severity:    RiskHigh,
				Description: "pyproject.toml contains insecure HTTP endpoints or remote curl/wget build hooks",
				Target:      pyprojectPath,
				Remediation: "Ensure build backends and package indexes use verified HTTPS channels.",
			})
		}
	}

	// 4. Inspect Rust build.rs for network calls, process execution, and env harvesting
	buildRsPath := filepath.Join(workspaceRoot, "build.rs")
	if data, err := os.ReadFile(buildRsPath); err == nil {
		content := string(data)
		if strings.Contains(content, "reqwest") || strings.Contains(content, "ureq") || strings.Contains(content, "TcpStream::connect") {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-RS-01",
				Severity:    RiskHigh,
				Description: "Rust build.rs contains outbound network socket connection logic",
				Target:      buildRsPath,
				Remediation: "Rust build scripts must not initiate network egress during compilation.",
			})
		}

		if strings.Contains(content, "std::process::Command") || strings.Contains(content, "Command::new") {
			if strings.Contains(content, `"sh"`) || strings.Contains(content, `"bash"`) || strings.Contains(content, `"curl"`) || strings.Contains(content, `"powershell"`) {
				report.Findings = append(report.Findings, Finding{
					RuleID:      "ARGUS-RS-02",
					Severity:    RiskHigh,
					Description: "Rust build.rs invokes external shell interpreter or network binary",
					Target:      buildRsPath,
					Remediation: "Avoid spawning shell processes in build.rs.",
				})
			}
		}

		if strings.Contains(content, "std::env::vars()") || strings.Contains(content, `env::var("AWS_`) || strings.Contains(content, `env::var("SSH_`) || strings.Contains(content, `env::var("GITHUB_TOKEN"`) {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-RS-03",
				Severity:    RiskHigh,
				Description: "Rust build.rs harvests host environment variables or sensitive keys",
				Target:      buildRsPath,
				Remediation: "Restrict environment variable access to standard Cargo build keys (e.g. TARGET, OUT_DIR).",
			})
		}
	}

	// 5. Inspect Go Ecosystem (go.mod replace directives & go:generate shell injections)
	report.Findings = append(report.Findings, InspectGoWorkspace(workspaceRoot)...)

	// 6. Inspect Ruby Ecosystem (Gemfile, *.gemspec, extconf.rb, Rakefile)
	report.Findings = append(report.Findings, InspectRubyWorkspace(workspaceRoot)...)

	// 7. Inspect Workspace Shell Scripts (*.sh, *.bash, *.zsh)
	report.Findings = append(report.Findings, InspectShellWorkspace(workspaceRoot)...)
}

func (e *Engine) runExternalTool(ctx context.Context, tool string, cmdArgs []string, workspaceRoot string, report *Report) error {
	execCtx, cancel := context.WithTimeout(ctx, 5*time.Second)
	defer cancel()

	args := append([]string{"inspect", "--json", "--workspace", workspaceRoot, "--"}, cmdArgs...)
	cmd := exec.CommandContext(execCtx, tool, args...)
	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("vet: external tool %s failed: %w", tool, err)
	}

	var extReport struct {
		Findings []Finding `json:"findings"`
	}
	if err := json.Unmarshal(out, &extReport); err == nil {
		report.Findings = append(report.Findings, extReport.Findings...)
	}

	return nil
}

func (e *Engine) evaluateRiskAndPolicy(report *Report) {
	ignored := make(map[string]bool, len(e.config.IgnoredRules))
	for _, ruleID := range e.config.IgnoredRules {
		ignored[strings.ToUpper(strings.TrimSpace(ruleID))] = true
	}

	var filtered []Finding
	for _, f := range report.Findings {
		if !ignored[strings.ToUpper(f.RuleID)] {
			filtered = append(filtered, f)
		}
	}
	report.Findings = filtered

	highest := RiskNone

	for _, f := range report.Findings {
		switch f.Severity {
		case RiskCritical:
			highest = RiskCritical
		case RiskHigh:
			if highest != RiskCritical {
				highest = RiskHigh
			}
		case RiskMedium:
			if highest != RiskCritical && highest != RiskHigh {
				highest = RiskMedium
			}
		case RiskLow:
			if highest == RiskNone {
				highest = RiskLow
			}
		}
	}

	report.MaxRisk = highest

	// In strict mode, High or Critical risk blocks execution
	if e.config.StrictMode && (highest == RiskHigh || highest == RiskCritical) {
		report.BlockExecution = true
	}
}

func hasExecutableOnPath(tool string) bool {
	p, err := exec.LookPath(tool)
	return err == nil && p != ""
}
