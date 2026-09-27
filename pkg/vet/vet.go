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

	if len(cmdArgs) == 0 {
		report.DurationMs = time.Since(start).Milliseconds()
		return report, nil
	}

	// 1. Heuristic Command Line Checks
	e.inspectCommandArgs(cmdArgs, report)

	// 2. Workspace Manifest Analysis (package.json, setup.py, Cargo.toml)
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
}

func (e *Engine) inspectWorkspaceManifests(workspaceRoot string, report *Report) {
	// 1. Inspect package.json for dangerous lifecycle scripts
	pkgJSONPath := filepath.Join(workspaceRoot, "package.json")
	if data, err := os.ReadFile(pkgJSONPath); err == nil {
		var manifest struct {
			Scripts map[string]string `json:"scripts"`
		}
		if err := json.Unmarshal(data, &manifest); err == nil {
			lifecycleHooks := []string{"preinstall", "install", "postinstall", "prepublish", "prepublishOnly"}
			obfuscationPatterns := []string{"base64", "eval(", "curl", "wget", "socket", "/dev/tcp"}

			for _, hook := range lifecycleHooks {
				script, exists := manifest.Scripts[hook]
				if !exists {
					continue
				}

				for _, pattern := range obfuscationPatterns {
					if strings.Contains(strings.ToLower(script), pattern) {
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
			}
		}
	}

	// 2. Inspect setup.py for raw reverse shells or unvetted network calls
	setupPyPath := filepath.Join(workspaceRoot, "setup.py")
	if data, err := os.ReadFile(setupPyPath); err == nil {
		content := string(data)
		if strings.Contains(content, "urllib.request") || strings.Contains(content, "requests.get") || strings.Contains(content, "exec(b64decode") {
			report.Findings = append(report.Findings, Finding{
				RuleID:      "ARGUS-PY-01",
				Severity:    RiskHigh,
				Description: "setup.py contains pre-execution network fetching or base64 execution",
				Target:      setupPyPath,
				Remediation: "Remove network calls from setup.py installer routines.",
			})
		}
	}
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
