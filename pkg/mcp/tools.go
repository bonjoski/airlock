package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/redact"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/vet"
)

// SupportedTools returns the specifications for all MCP tools exposed by Airlock.
func SupportedTools() []Tool {
	return []Tool{
		{
			Name: "airlock_exec",
			Description: "Executes a command safely inside the Airlock zero-trust sandbox confinement. " +
				"Enforces OS-level isolation (Apple Seatbelt / Linux bwrap), fail-closed proxy egress filtering, " +
				"ephemeral scratch staging, environment sanitization, and structured audit logging.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"command": {
						Type:        "string",
						Description: "The command line or executable to execute inside the sandbox (e.g. 'npm install', 'python build.py').",
					},
					"args": {
						Type:        "array",
						Description: "Optional list of command arguments. If provided alongside 'command', they are appended.",
						Items: map[string]interface{}{
							"type": "string",
						},
					},
					"workspace": {
						Type:        "string",
						Description: "Workspace directory root to isolate. Defaults to current working directory or detected Git root.",
					},
					"config_path": {
						Type:        "string",
						Description: "Optional explicit path to an airlock.yaml declarative policy file.",
					},
					"airgap": {
						Type:        "boolean",
						Description: "Enforce complete offline isolation, denying all outbound network connections.",
						Default:     false,
					},
					"allow_network": {
						Type:        "boolean",
						Description: "Permit direct external outbound networking (development bypass).",
						Default:     false,
					},
					"allow_domains": {
						Type:        "array",
						Description: "Additional external domain names to permit through the egress proxy (e.g. ['api.github.com']).",
						Items: map[string]interface{}{
							"type": "string",
						},
					},
					"keep_env": {
						Type:        "array",
						Description: "Environment variable names to preserve across the sandbox boundary.",
						Items: map[string]interface{}{
							"type": "string",
						},
					},
					"timeout_seconds": {
						Type:        "integer",
						Description: "Maximum execution timeout in seconds. Defaults to 120 seconds.",
						Default:     120,
					},
				},
				Required: []string{"command"},
			},
		},
		{
			Name: "airlock_vet",
			Description: "Performs Argus static analysis to detect supply-chain vulnerabilities, typosquatting packages, " +
				"obfuscated setup.py scripts, and malicious build.rs network logic prior to execution.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"command": {
						Type:        "string",
						Description: "The package installation or shell command string to inspect for typosquatting and dangerous syntax.",
					},
					"workspace": {
						Type:        "string",
						Description: "Workspace directory to inspect for suspicious setup.py, build.rs, or manifest files.",
					},
					"strict": {
						Type:        "boolean",
						Description: "If true, treat High and Critical security findings as fatal policy violations.",
						Default:     true,
					},
				},
			},
		},
		{
			Name: "airlock_policy_check",
			Description: "Checks whether specific domains, filesystem paths, or environment variables comply with " +
				"the active declarative policy (airlock.yaml) and zero-trust invariant guardrails.",
			InputSchema: InputSchema{
				Type: "object",
				Properties: map[string]PropertyDef{
					"workspace": {
						Type:        "string",
						Description: "Workspace directory containing airlock.yaml.",
					},
					"config_path": {
						Type:        "string",
						Description: "Optional explicit path to an airlock.yaml declarative policy file.",
					},
					"domain": {
						Type:        "string",
						Description: "Domain name to test against egress proxy allowlists.",
					},
					"path": {
						Type:        "string",
						Description: "Filesystem path to test against read/write guardrails and policies.",
					},
					"env_var": {
						Type:        "string",
						Description: "Environment variable name to test against sanitization and deny lists.",
					},
				},
			},
		},
	}
}

// ToolHandler defines the interface for handling MCP tool calls.
type ToolHandler interface {
	HandleExec(ctx context.Context, args json.RawMessage) (*CallToolResult, error)
	HandleVet(ctx context.Context, args json.RawMessage) (*CallToolResult, error)
	HandlePolicyCheck(ctx context.Context, args json.RawMessage) (*CallToolResult, error)
}

// DefaultToolHandler implements ToolHandler using standard Airlock libraries.
type DefaultToolHandler struct{}

// NewDefaultToolHandler creates a new default tool handler.
func NewDefaultToolHandler() *DefaultToolHandler {
	return &DefaultToolHandler{}
}

// ExecArgs represents input arguments for airlock_exec.
type ExecArgs struct {
	Command        string   `json:"command"`
	Args           []string `json:"args,omitempty"`
	Workspace      string   `json:"workspace,omitempty"`
	ConfigPath     string   `json:"config_path,omitempty"`
	Airgap         bool     `json:"airgap,omitempty"`
	AllowNetwork   bool     `json:"allow_network,omitempty"`
	AllowDomains   []string `json:"allow_domains,omitempty"`
	KeepEnv        []string `json:"keep_env,omitempty"`
	TimeoutSeconds int      `json:"timeout_seconds,omitempty"`
}

// ExecResult represents structured execution output.
type ExecResult struct {
	ExitCode       int      `json:"exit_code"`
	Stdout         string   `json:"stdout"`
	Stderr         string   `json:"stderr"`
	DurationMs     int64    `json:"duration_ms"`
	Airgap         bool     `json:"airgap"`
	AllowedDomains []string `json:"allowed_domains"`
	Error          string   `json:"error,omitempty"`
}

func (h *DefaultToolHandler) HandleExec(ctx context.Context, rawArgs json.RawMessage) (*CallToolResult, error) {
	var args ExecArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, fmt.Errorf("failed to parse airlock_exec arguments: %w", err)
	}

	if strings.TrimSpace(args.Command) == "" {
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "error: 'command' argument is required"}},
			IsError: true,
		}, nil
	}

	// 1. Resolve Command tokens
	var cmdTokens []string
	if len(args.Args) > 0 {
		cmdTokens = append([]string{args.Command}, args.Args...)
	} else {
		cmdTokens = strings.Fields(args.Command)
	}

	if len(cmdTokens) == 0 {
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: "error: command must contain at least one token"}},
			IsError: true,
		}, nil
	}

	// 2. Resolve Workspace
	workspaceRoot := args.Workspace
	if workspaceRoot == "" {
		cwd, err := os.Getwd()
		if err == nil {
			workspaceRoot = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	// 3. Load Declarative Config
	var loadedCfg *config.Config
	discoveredConfigPath := args.ConfigPath
	if discoveredConfigPath != "" {
		cfg, err := config.LoadFromFile(discoveredConfigPath)
		if err == nil {
			loadedCfg = cfg
		}
	} else {
		p, cfg, err := config.DiscoverConfig(workspaceRoot)
		if err == nil && cfg != nil {
			loadedCfg = cfg
			discoveredConfigPath = p
		}
	}

	airgap := args.Airgap
	extraDomains := append([]string(nil), args.AllowDomains...)
	keptEnvVars := append([]string(nil), args.KeepEnv...)
	var deniedEnvVars []string
	var extraAllowRead []string
	var extraAllowWrite []string
	var extraDenyRead []string
	var extraDenyWrite []string
	var ignoredVetRules []string
	vetEnabled := false
	vetStrict := false

	if loadedCfg != nil {
		config.SanitizeAndEnforceGuardrails(loadedCfg)
		if loadedCfg.Network.Airgap && !args.AllowNetwork {
			airgap = true
		}
		extraDomains = append(extraDomains, loadedCfg.Network.AllowDomains...)
		keptEnvVars = append(keptEnvVars, loadedCfg.Env.Allow...)
		deniedEnvVars = append(deniedEnvVars, loadedCfg.Env.Deny...)
		extraAllowRead = append(extraAllowRead, loadedCfg.Filesystem.AllowRead...)
		extraAllowWrite = append(extraAllowWrite, loadedCfg.Filesystem.AllowWrite...)
		extraDenyRead = append(extraDenyRead, loadedCfg.Filesystem.DenyRead...)
		extraDenyWrite = append(extraDenyWrite, loadedCfg.Filesystem.DenyWrite...)
		if loadedCfg.Vetting.Enable {
			vetEnabled = true
		}
		if loadedCfg.Vetting.Strict {
			vetStrict = true
		}
		ignoredVetRules = append(ignoredVetRules, loadedCfg.Vetting.IgnoredRules...)
	}

	// 4. Setup buffers
	var stdoutBuf bytes.Buffer
	var stderrBuf bytes.Buffer

	// 5. Setup logger
	auditLogger, _ := audit.NewDefaultLogger()
	var effectiveLogger audit.Logger = &audit.NopLogger{}
	if auditLogger != nil {
		defer func() { _ = auditLogger.Close() }()
		effectiveLogger = auditLogger
	}

	opts := sandbox.Options{
		WorkspaceRoot:   workspaceRoot,
		ConfigPath:      discoveredConfigPath,
		Airgap:          airgap,
		AllowDirectNet:  args.AllowNetwork,
		AllowedDomains:  extraDomains,
		KeepEnv:         keptEnvVars,
		DenyEnv:         deniedEnvVars,
		ExtraAllowRead:  extraAllowRead,
		ExtraAllowWrite: extraAllowWrite,
		ExtraDenyRead:   extraDenyRead,
		ExtraDenyWrite:  extraDenyWrite,
		NonInteractive:  true,
		AuditLogger:     effectiveLogger,
		VetEnabled:      vetEnabled,
		VetStrict:       vetStrict,
		IgnoredVetRules: ignoredVetRules,
		Stdout:          &stdoutBuf,
		Stderr:          &stderrBuf,
	}

	eng, err := sandbox.NewEngine(opts)
	if err != nil {
		return &CallToolResult{
			Content: []ContentItem{{Type: "text", Text: fmt.Sprintf("failed to initialize sandbox engine: %v", err)}},
			IsError: true,
		}, nil
	}

	// 6. Timeout handling
	timeoutSec := args.TimeoutSeconds
	if timeoutSec <= 0 {
		timeoutSec = 120
	}
	execCtx, cancel := context.WithTimeout(ctx, time.Duration(timeoutSec)*time.Second)
	defer cancel()

	start := time.Now()
	exitCode, execErr := eng.Execute(execCtx, cmdTokens)
	duration := time.Since(start)

	res := ExecResult{
		ExitCode:       exitCode,
		Stdout:         redact.RedactString(stdoutBuf.String()),
		Stderr:         redact.RedactString(stderrBuf.String()),
		DurationMs:     duration.Milliseconds(),
		Airgap:         airgap,
		AllowedDomains: extraDomains,
	}
	if execErr != nil {
		res.Error = execErr.Error()
	}

	resBytes, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format execution result: %w", err)
	}

	return &CallToolResult{
		Content: []ContentItem{{Type: "text", Text: string(resBytes)}},
		IsError: exitCode != 0,
	}, nil
}

// VetArgs represents input arguments for airlock_vet.
type VetArgs struct {
	Command   string `json:"command,omitempty"`
	Workspace string `json:"workspace,omitempty"`
	Strict    bool   `json:"strict,omitempty"`
}

// VetFinding represents a single finding in the report.
type VetFinding struct {
	RuleID      string `json:"rule_id"`
	Severity    string `json:"severity"`
	Description string `json:"description"`
	Target      string `json:"target,omitempty"`
}

// VetResult represents structured static analysis output.
type VetResult struct {
	Passed       bool         `json:"passed"`
	Strict       bool         `json:"strict"`
	TotalIssues  int          `json:"total_issues"`
	HighCritical int          `json:"high_critical_issues"`
	Findings     []VetFinding `json:"findings"`
	Summary      string       `json:"summary"`
}

func (h *DefaultToolHandler) HandleVet(ctx context.Context, rawArgs json.RawMessage) (*CallToolResult, error) {
	var args VetArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, fmt.Errorf("failed to parse airlock_vet arguments: %w", err)
		}
	}

	eng := vet.NewEngine(vet.Config{
		StrictMode: args.Strict,
	})

	var cmdTokens []string
	if strings.TrimSpace(args.Command) != "" {
		cmdTokens = strings.Fields(args.Command)
	}

	targetWorkspace := args.Workspace
	if targetWorkspace == "" && len(cmdTokens) == 0 {
		cwd, err := os.Getwd()
		if err == nil {
			targetWorkspace = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	report, err := eng.Inspect(ctx, cmdTokens, targetWorkspace)
	if err != nil {
		return nil, fmt.Errorf("argus inspection failed: %w", err)
	}

	var findingsList []VetFinding
	highCriticalCount := 0

	for _, f := range report.Findings {
		findingsList = append(findingsList, VetFinding{
			RuleID:      f.RuleID,
			Severity:    string(f.Severity),
			Description: f.Description,
			Target:      f.Target,
		})
		if f.Severity == vet.RiskHigh || f.Severity == vet.RiskCritical {
			highCriticalCount++
		}
	}

	passed := !report.BlockExecution
	if !args.Strict && len(findingsList) > 0 {
		passed = true
	}

	summary := "Argus static analysis passed with no blocking issues."
	if !passed {
		summary = fmt.Sprintf("Argus detected %d High/Critical security violations (strict mode blocked execution).", highCriticalCount)
	} else if len(findingsList) > 0 {
		summary = fmt.Sprintf("Argus detected %d informational/low issues.", len(findingsList))
	}

	res := VetResult{
		Passed:       passed,
		Strict:       args.Strict,
		TotalIssues:  len(findingsList),
		HighCritical: highCriticalCount,
		Findings:     findingsList,
		Summary:      summary,
	}

	resBytes, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format vet result: %w", err)
	}

	return &CallToolResult{
		Content: []ContentItem{{Type: "text", Text: string(resBytes)}},
		IsError: !passed,
	}, nil
}

// PolicyCheckArgs represents input arguments for airlock_policy_check.
type PolicyCheckArgs struct {
	Workspace  string `json:"workspace,omitempty"`
	ConfigPath string `json:"config_path,omitempty"`
	Domain     string `json:"domain,omitempty"`
	Path       string `json:"path,omitempty"`
	EnvVar     string `json:"env_var,omitempty"`
}

// PolicyCheckResult represents structured policy evaluation output.
type PolicyCheckResult struct {
	ConfigFound     bool                   `json:"config_found"`
	ConfigPath      string                 `json:"config_path,omitempty"`
	Mode            string                 `json:"mode"`
	Airgap          bool                   `json:"airgap"`
	DomainCheck     map[string]interface{} `json:"domain_check,omitempty"`
	PathCheck       map[string]interface{} `json:"path_check,omitempty"`
	EnvCheck        map[string]interface{} `json:"env_check,omitempty"`
	GuardrailAlerts []string               `json:"guardrail_alerts,omitempty"`
}

func (h *DefaultToolHandler) HandlePolicyCheck(ctx context.Context, rawArgs json.RawMessage) (*CallToolResult, error) {
	var args PolicyCheckArgs
	if len(rawArgs) > 0 {
		if err := json.Unmarshal(rawArgs, &args); err != nil {
			return nil, fmt.Errorf("failed to parse airlock_policy_check arguments: %w", err)
		}
	}

	workspaceRoot := args.Workspace
	if workspaceRoot == "" {
		cwd, err := os.Getwd()
		if err == nil {
			workspaceRoot = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	var loadedCfg *config.Config
	configPath := args.ConfigPath
	if configPath != "" {
		cfg, err := config.LoadFromFile(configPath)
		if err == nil {
			loadedCfg = cfg
		}
	} else {
		p, cfg, err := config.DiscoverConfig(workspaceRoot)
		if err == nil && cfg != nil {
			loadedCfg = cfg
			configPath = p
		}
	}

	if loadedCfg == nil {
		loadedCfg = config.DefaultConfig()
	}

	issues := config.SanitizeAndEnforceGuardrails(loadedCfg)
	var alertStrings []string
	for _, issue := range issues {
		alertStrings = append(alertStrings, fmt.Sprintf("[%s] %s: %s", issue.Severity, issue.Field, issue.Message))
	}

	res := PolicyCheckResult{
		ConfigFound:     configPath != "",
		ConfigPath:      configPath,
		Mode:            string(loadedCfg.Mode),
		Airgap:          loadedCfg.Network.Airgap,
		GuardrailAlerts: alertStrings,
	}

	// 1. Evaluate Domain if requested
	if strings.TrimSpace(args.Domain) != "" {
		targetDomain := strings.TrimSpace(args.Domain)
		allowed := false
		reason := "Blocked: not present in allowed domains or airgap mode active"

		if !loadedCfg.Network.Airgap {
			// Check standard baseline domains
			baselineDomains := []string{
				"registry.npmjs.org", "registry.yarnpkg.com", "pypi.org",
				"files.pythonhosted.org", "crates.io", "static.crates.io",
				"index.crates.io", "proxy.golang.org", "sum.golang.org",
			}
			if config.MatchAnyDomain(baselineDomains, targetDomain) {
				allowed = true
				reason = "Permitted: matches baseline standard package registry"
			} else if config.MatchAnyDomain(loadedCfg.Network.AllowDomains, targetDomain) {
				allowed = true
				reason = "Permitted: matches declarative policy allow_domains rule"
			}
		}

		res.DomainCheck = map[string]interface{}{
			"domain":  targetDomain,
			"allowed": allowed,
			"reason":  reason,
		}
	}

	// 2. Evaluate Path if requested
	if strings.TrimSpace(args.Path) != "" {
		targetPath := strings.TrimSpace(args.Path)
		cleanPath := filepath.Clean(targetPath)

		isForbidden := false
		forbiddenReason := ""

		// Check guardrails against secrets
		homeDir, _ := os.UserHomeDir()
		if (homeDir != "" && strings.HasPrefix(cleanPath, filepath.Join(homeDir, ".ssh"))) || strings.HasPrefix(targetPath, "~/.ssh") {
			isForbidden = true
			forbiddenReason = "Strictly blocked by Airlock Guardrail: SSH credentials cannot be accessed."
		} else if (homeDir != "" && strings.HasPrefix(cleanPath, filepath.Join(homeDir, ".aws"))) || strings.HasPrefix(targetPath, "~/.aws") {
			isForbidden = true
			forbiddenReason = "Strictly blocked by Airlock Guardrail: AWS credentials cannot be accessed."
		} else if cleanPath == "/var/run/docker.sock" {
			isForbidden = true
			forbiddenReason = "Strictly blocked by Airlock Guardrail: Docker daemon socket cannot be accessed."
		} else if strings.Contains(cleanPath, ".git/hooks") {
			isForbidden = true
			forbiddenReason = "Strictly blocked by Airlock Guardrail: Git persistence hooks are write-protected."
		}

		res.PathCheck = map[string]interface{}{
			"path":                 targetPath,
			"guardrail_restricted": isForbidden,
			"status": func() string {
				if isForbidden {
					return "DENIED"
				}
				return "PERMITTED_IN_SANDBOX"
			}(),
			"reason": forbiddenReason,
		}
	}

	// 3. Evaluate Env Var if requested
	if strings.TrimSpace(args.EnvVar) != "" {
		envVar := strings.TrimSpace(args.EnvVar)
		forbidden := false
		reason := "Permitted if present in allowlist"

		if envVar == "LD_PRELOAD" || envVar == "DYLD_INSERT_LIBRARIES" || envVar == "DYLD_LIBRARY_PATH" {
			forbidden = true
			reason = "Strictly stripped by Airlock Guardrail: Dynamic linker injection variable."
		}

		res.EnvCheck = map[string]interface{}{
			"variable":             envVar,
			"guardrail_restricted": forbidden,
			"reason":               reason,
		}
	}

	resBytes, err := json.MarshalIndent(res, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to format policy check result: %w", err)
	}

	return &CallToolResult{
		Content: []ContentItem{{Type: "text", Text: string(resBytes)}},
		IsError: false,
	}, nil
}
