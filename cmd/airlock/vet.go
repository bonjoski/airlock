package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/profile"
	"github.com/bonjoski/airlock/pkg/seatbelt"
	"github.com/bonjoski/airlock/pkg/ux"
	"github.com/bonjoski/airlock/pkg/vet"
	"gopkg.in/yaml.v3"
)

func handleVet(args []string) {
	os.Exit(runVet(args, os.Stdout, os.Stderr))
}

func runVet(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("airlock vet", flag.ContinueOnError)
	fs.SetOutput(stderr)

	strict := fs.Bool("strict", true, "Fail closed on High/Critical supply-chain findings and Siren sandbox misconfigurations (exit 30)")
	workspace := fs.String("workspace", "", "Override workspace directory to inspect")
	dirFlag := fs.String("dir", "", "Alias for --workspace: directory to inspect")
	profileName := fs.String("profile", "", "Execution profile to compile and lint in strict mode")
	configPath := fs.String("config", "", "Explicit path to airlock.yaml / .airlock.yaml policy file")
	sbplPath := fs.String("sbpl", "", "Optional path to compiled SBPL or Landlock policy file to lint directly")
	jsonOut := fs.Bool("json", false, "Output report as structured JSON")
	showWhy := fs.Bool("why", false, "Progressive disclosure: expand Siren finding details and remediation guidance")
	vetTool := fs.String("vetpkg", "", "Optional path to external vetpkg / argus binary analyzer")

	cmdIndex := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIndex = i
			break
		}
	}

	var flagArgs []string
	var cmdArgs []string
	if cmdIndex != -1 {
		flagArgs = args[:cmdIndex]
		cmdArgs = args[cmdIndex+1:]
	} else {
		flagArgs = args
	}

	if err := fs.Parse(flagArgs); err != nil {
		return 1
	}

	ws := *workspace
	if ws == "" && *dirFlag != "" {
		ws = *dirFlag
	}
	if ws == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(stderr, "airlock vet: failed to get working directory: %v\n", err)
			return 1
		}
		ws = cwd
	}

	absWS, err := filepath.Abs(ws)
	if err != nil {
		fmt.Fprintf(stderr, "airlock vet: invalid workspace path: %v\n", err)
		return 1
	}

	// 1. In --strict mode, run Siren hard-boundary profile linter first (RFC-2026-11-27-67)
	var sirenFindings []vet.SirenFinding
	if *strict {
		rawCfg, effectiveCfg, cfgErr := loadVetConfigs(absWS, *configPath, *profileName)
		if cfgErr != nil {
			ffe := &ux.FixForwardError{
				Tool:           "airlock",
				Code:           "AIRLOCK_SIREN_CONFIG_ERROR",
				Summary:        fmt.Sprintf("Failed to load policy config for strict linting: %v", cfgErr),
				RemediationCmd: "airlock config validate",
				WhyOneLiner:    "Strict profile vetting fails closed when policy configuration cannot be parsed.",
				DeepWhy:        cfgErr.Error(),
				References:     []string{"RFC-2026-11-27-67", "CWE-250"},
				ExitCode:       vet.SirenExitCode,
			}
			_ = ffe.Render(stderr, *jsonOut, *showWhy)
			return vet.SirenExitCode
		}

		compiledProfile, compileErr := loadOrCompileProfile(absWS, *sbplPath, *profileName, effectiveCfg)
		if compileErr != nil {
			ffe := &ux.FixForwardError{
				Tool:           "airlock",
				Code:           "AIRLOCK_SIREN_COMPILE_ERROR",
				Summary:        fmt.Sprintf("Failed to synthesize sandbox profile for strict linting: %v", compileErr),
				RemediationCmd: "airlock doctor",
				WhyOneLiner:    "Strict profile vetting compiles the effective sandbox profile to verify kernel boundaries.",
				DeepWhy:        compileErr.Error(),
				References:     []string{"RFC-2026-11-27-67", "CWE-250"},
				ExitCode:       vet.SirenExitCode,
			}
			_ = ffe.Render(stderr, *jsonOut, *showWhy)
			return vet.SirenExitCode
		}

		lintTargetCfg := rawCfg
		if lintTargetCfg == nil {
			lintTargetCfg = effectiveCfg
		}

		var sirenErr error
		sirenFindings, sirenErr = vet.VetProfileStrict(lintTargetCfg, compiledProfile)
		if sirenErr != nil {
			ffe := &ux.FixForwardError{
				Tool:           "airlock",
				Code:           "AIRLOCK_SIREN_PARSE_ERROR",
				Summary:        fmt.Sprintf("Compiled profile failed strict AST verification: %v", sirenErr),
				RemediationCmd: "airlock init --force",
				WhyOneLiner:    "Airlock fails closed when a compiled sandbox profile contains malformed or unbalanced syntax.",
				DeepWhy:        sirenErr.Error(),
				References:     []string{"RFC-2026-11-27-67", "CWE-250"},
				ExitCode:       vet.SirenExitCode,
			}
			if *jsonOut {
				_ = ffe.Render(stdout, true, *showWhy)
			} else {
				_ = ffe.Render(stderr, false, *showWhy)
			}
			return vet.SirenExitCode
		}

		if len(sirenFindings) > 0 {
			ffe := buildSirenFixForwardError(sirenFindings)
			if *jsonOut {
				payload := struct {
					ExitCode        int                  `json:"exit_code"`
					BlockExecution  bool                 `json:"block_execution"`
					SirenFindings   []vet.SirenFinding   `json:"siren_findings"`
					FixForwardError *ux.FixForwardError  `json:"fix_forward_error"`
				}{
					ExitCode:        vet.SirenExitCode,
					BlockExecution:  true,
					SirenFindings:   sirenFindings,
					FixForwardError: ffe,
				}
				enc := json.NewEncoder(stdout)
				enc.SetEscapeHTML(false)
				enc.SetIndent("", "  ")
				_ = enc.Encode(payload)
			} else {
				_ = ffe.Render(stderr, false, *showWhy)
			}
			return vet.SirenExitCode
		}
	}

	// 2. Run Argus supply-chain static analysis & manifest inspection
	engine := vet.NewEngine(vet.Config{
		StrictMode:   *strict,
		ExternalTool: *vetTool,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := engine.Inspect(ctx, cmdArgs, absWS)
	if err != nil {
		fmt.Fprintf(stderr, "airlock vet: inspection failed: %v\n", err)
		return 1
	}

	if *jsonOut {
		payload := struct {
			*vet.Report
			SirenFindings []vet.SirenFinding `json:"siren_findings"`
		}{
			Report:        report,
			SirenFindings: sirenFindings,
		}
		if payload.SirenFindings == nil {
			payload.SirenFindings = []vet.SirenFinding{}
		}
		data, _ := json.MarshalIndent(payload, "", "  ")
		fmt.Fprintln(stdout, string(data))
	} else {
		fmt.Fprintln(stdout, "Argus Supply Chain Static Analysis & Threat Inspection")
		fmt.Fprintln(stdout, "=======================================================")
		fmt.Fprintf(stdout, "Workspace Root: %s\n", absWS)
		if len(cmdArgs) > 0 {
			fmt.Fprintf(stdout, "Target Command: %s\n", strings.Join(cmdArgs, " "))
		}
		fmt.Fprintf(stdout, "Duration:       %d ms\n", report.DurationMs)
		fmt.Fprintf(stdout, "Overall Risk:   %s\n", report.MaxRisk)
		if *strict {
			fmt.Fprintln(stdout, "Siren Profile:  PASS (0 hard-boundary misconfigurations)")
		}
		fmt.Fprintln(stdout)

		if len(report.Findings) == 0 {
			fmt.Fprintln(stdout, "  ✓ PASS: Zero supply-chain threats or suspicious lifecycle hooks detected.")
		} else {
			for _, f := range report.Findings {
				var sym string
				switch f.Severity {
				case vet.RiskCritical, vet.RiskHigh:
					sym = "❌"
				case vet.RiskMedium:
					sym = "⚠️"
				default:
					sym = "ℹ️"
				}
				fmt.Fprintf(stdout, "  %s [%s] %s: %s\n", sym, f.Severity, f.RuleID, f.Description)
				if f.Target != "" {
					fmt.Fprintf(stdout, "         Target: %s\n", f.Target)
				}
				if f.Remediation != "" {
					fmt.Fprintf(stdout, "         Action: %s\n", f.Remediation)
				}
			}
		}
		fmt.Fprintln(stdout, "-------------------------------------------------------")
		if report.BlockExecution {
			fmt.Fprintf(stdout, "Status: BLOCKED (%d finding(s) require remediation before execution)\n", len(report.Findings))
		} else {
			fmt.Fprintln(stdout, "Status: PASSED")
		}
	}

	if report.BlockExecution {
		return 1
	}
	return 0
}

func buildSirenFixForwardError(findings []vet.SirenFinding) *ux.FixForwardError {
	first := findings[0]
	remediation := first.RemediationCmd
	if remediation == "" {
		remediation = "airlock init --force"
	}

	var deepLines []string
	for _, f := range findings {
		deepLines = append(deepLines, fmt.Sprintf("[%s] %s (%s): %s", strings.ToUpper(f.Severity), f.RuleID, f.Location, f.Summary))
	}

	summary := fmt.Sprintf("Blocked by %d Siren sandbox misconfiguration(s): %s", len(findings), first.Summary)
	if len(findings) == 1 {
		summary = fmt.Sprintf("Siren lint blocked (%s): %s", first.RuleID, first.Summary)
	}

	return &ux.FixForwardError{
		Tool:           "airlock",
		Code:           "AIRLOCK_SIREN_MISCONFIG",
		Summary:        summary,
		RemediationCmd: remediation,
		WhyOneLiner:    "Strict profile linting blocks weak sandbox boundaries (broad reads, missing credential denies, wildcard egress, or fail-open settings) before execution.",
		DeepWhy:        strings.Join(deepLines, "\n"),
		References:     []string{"RFC-2026-11-27-67", "CWE-250", "CWE-732"},
		ExitCode:       vet.SirenExitCode,
	}
}

// loadVetConfigs reads the raw (pre-sanitization) workspace/explicit config so strict linting
// detects attempted policy weakenings (e.g., mode: permissive, allow_read: ~/.ssh, wildcard allow_domains),
// while also computing the effective merged config for profile synthesis.
func loadVetConfigs(workspaceRoot, explicitConfigPath, profileName string) (rawCfg *config.Config, effectiveCfg *config.Config, err error) {
	if profileName != "" {
		prof, profErr := config.GetBuiltinProfile(profileName)
		if profErr != nil {
			return nil, nil, profErr
		}
		effectiveCfg = prof
	}

	cfgFile := explicitConfigPath
	if cfgFile == "" && workspaceRoot != "" {
		for _, name := range config.ConfigFileNames {
			candidate := filepath.Join(workspaceRoot, name)
			if fi, statErr := os.Stat(candidate); statErr == nil && !fi.IsDir() {
				cfgFile = candidate
				break
			}
		}
	}

	if cfgFile != "" {
		parsedRaw, parseErr := parseRawConfigFile(cfgFile)
		if parseErr != nil {
			return nil, nil, parseErr
		}
		rawCfg = parsedRaw

		sanitized, loadErr := config.LoadFromFile(cfgFile)
		if loadErr != nil {
			return nil, nil, loadErr
		}
		if effectiveCfg != nil {
			effectiveCfg = config.MergeProfiles(effectiveCfg, sanitized)
		} else {
			effectiveCfg = sanitized
		}
	}

	if effectiveCfg == nil {
		effectiveCfg = config.DefaultConfig()
	}

	return rawCfg, effectiveCfg, nil
}

func parseRawConfigFile(path string) (*config.Config, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	cfg := config.DefaultConfig()
	ext := strings.ToLower(filepath.Ext(path))
	if ext == ".json" || (ext == "" && strings.HasSuffix(filepath.Base(path), ".airlockrc")) {
		if err := json.Unmarshal(data, cfg); err != nil {
			if yamlErr := yaml.Unmarshal(data, cfg); yamlErr != nil {
				return nil, err
			}
		}
	} else {
		if err := yaml.Unmarshal(data, cfg); err != nil {
			return nil, err
		}
	}
	return cfg, nil
}

func loadOrCompileProfile(workspaceRoot, sbplPath, profileName string, cfg *config.Config) (string, error) {
	if sbplPath != "" {
		data, err := os.ReadFile(sbplPath)
		if err != nil {
			return "", fmt.Errorf("read compiled profile %q: %w", sbplPath, err)
		}
		return string(data), nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil || homeDir == "" {
		homeDir = "/Users/developer"
	}
	scratchDir := filepath.Join(os.TempDir(), "airlock-vet-scratch")

	proxyPort := 18443
	airgap := false
	if cfg != nil && cfg.Network.Airgap {
		airgap = true
		proxyPort = 0
	}

	params := seatbelt.Params{
		Profile:              profileName,
		UserHome:             homeDir,
		WorkspaceRoot:        workspaceRoot,
		ScratchDir:           scratchDir,
		Airgap:               airgap,
		ProxyPort:            proxyPort,
		AntiLoopback:         cfg != nil && cfg.Network.AntiLoopback,
		AllowedUnixSockets:   cfg.Network.AllowedUnixSockets,
		AllowedLoopbackPorts: cfg.Network.AllowedLoopbackPorts,
		ExtraAllowRead:       cfg.Filesystem.AllowRead,
		ExtraAllowWrite:      cfg.Filesystem.AllowWrite,
		ExtraDenyRead:        cfg.Filesystem.DenyRead,
		ExtraDenyWrite:       cfg.Filesystem.DenyWrite,
	}

	switch strings.ToLower(strings.TrimSpace(profileName)) {
	case "untrusted-agent", "untrusted_agent":
		return profile.GenerateUntrustedAgentSeatbelt(params, profile.UntrustedAgentConfig{
			WorkDir:          workspaceRoot,
			AllowEgressHosts: cfg.Network.AllowDomains,
		})
	case "dev-agent", "dev_agent":
		return profile.GenerateDevAgentSeatbelt(params)
	case "mcp-gateway", "mcp_gateway":
		return profile.GenerateMCPGatewaySeatbelt(params)
	case "web-worker", "web_worker":
		return profile.GenerateWebWorkerSeatbelt(params)
	default:
		return seatbelt.NewGenerator().Generate(params)
	}
}
