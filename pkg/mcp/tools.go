package mcp

import (
	"bytes"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/redact"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/secrets"
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
					"secret_leases": {
						Type:        "array",
						Description: "Opaque Locksmith lease handles (lease_...) redeemed directly inside the sandbox without exposing secret bytes to the LLM.",
						Items: map[string]interface{}{
							"type": "string",
						},
					},
					"session_id": {
						Type:        "string",
						Description: "Optional Fabrial session identifier (sess_...) for opaque lease binding and BLPR-v1 receipt correlation. Defaults to FABRIAL_SESSION_ID.",
					},
					"emit_receipt": {
						Type:        "boolean",
						Description: "Emit a BLPR-v1 DSSE/in-toto receipt under FABRIAL_RECEIPT_DIR. Defaults to true when FABRIAL_SESSION_ID or session_id is set.",
						Default:     true,
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
					"session_id": {
						Type:        "string",
						Description: "Optional Fabrial session identifier (sess_...) for BLPR-v1 receipt correlation. Defaults to FABRIAL_SESSION_ID.",
					},
					"emit_receipt": {
						Type:        "boolean",
						Description: "Emit a BLPR-v1 DSSE/in-toto receipt under FABRIAL_RECEIPT_DIR. Defaults to true when FABRIAL_SESSION_ID or session_id is set.",
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
	SecretLeases   []string `json:"secret_leases,omitempty"`
	SessionID      string   `json:"session_id,omitempty"`
	EmitReceipt    *bool    `json:"emit_receipt,omitempty"`
}

// ExecResult represents structured execution output.
type ExecResult = sandbox.ExecResult

type redeemedLease struct {
	envVar string
	secret []byte
}

func resolveSessionID(explicit string) string {
	if s := strings.TrimSpace(explicit); s != "" {
		return s
	}
	return strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
}

func shouldEmitReceipt(explicit *bool, sessionID string) bool {
	if explicit != nil {
		return *explicit
	}
	return sessionID != "" || strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR")) != ""
}

func kernelBackendName() string {
	switch runtime.GOOS {
	case "darwin":
		return "seatbelt"
	case "linux":
		return "landlock"
	case "windows":
		return "job_object"
	default:
		return runtime.GOOS
	}
}

func detectLeasedSecretLeak(stdout, stderr []byte, leases []redeemedLease) (string, bool) {
	for _, l := range leases {
		if len(l.secret) == 0 {
			continue
		}
		if bytes.Contains(stdout, l.secret) || bytes.Contains(stderr, l.secret) {
			return l.envVar, true
		}
		if len(l.secret) >= 8 {
			encoded := make([]byte, base64.StdEncoding.EncodedLen(len(l.secret)))
			base64.StdEncoding.Encode(encoded, l.secret)
			leaked := bytes.Contains(stdout, encoded) || bytes.Contains(stderr, encoded)
			clear(encoded)
			if leaked {
				return l.envVar, true
			}
		}
	}
	return "", false
}

func isSandboxDenial(execErr error, stderrStr, stdoutStr string) bool {
	combined := strings.ToLower(stderrStr + "\n" + stdoutStr)
	if execErr != nil {
		combined += "\n" + strings.ToLower(execErr.Error())
	}
	signals := []string{
		"operation not permitted",
		"permission denied",
		"read-only file system",
		"sandbox-exec",
		"seatbelt",
		"landlock",
		"seccomp",
		"bwrap",
		"unprivileged user namespaces are disabled",
		"airgap",
		"egress",
		"blocked by zero-trust",
		"proxy refused",
		"403 forbidden",
		"sandbox: ",
	}
	for _, sig := range signals {
		if strings.Contains(combined, sig) {
			return true
		}
	}
	// On Linux bwrap, masked host credential paths are overmounted with /dev/null or empty tmpfs,
	// yielding "not a directory" or "no such file or directory" when a confined command probes them.
	if strings.Contains(combined, "not a directory") || strings.Contains(combined, "no such file or directory") {
		maskedPaths := []string{
			"/.ssh", "/.aws", "/.gnupg", "/.kube", "/.docker",
			"/.config/gcloud", "/.npmrc", "/.netrc", "/.pypirc", "/.git-credentials",
		}
		for _, mp := range maskedPaths {
			if strings.Contains(combined, mp) {
				return true
			}
		}
	}
	return false
}

func (h *DefaultToolHandler) HandleExec(ctx context.Context, rawArgs json.RawMessage) (*CallToolResult, error) {
	var args ExecArgs
	if err := json.Unmarshal(rawArgs, &args); err != nil {
		return nil, fmt.Errorf("failed to parse airlock_exec arguments: %w", err)
	}

	if strings.TrimSpace(args.Command) == "" {
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_INVALID_ARGS",
			ExitCode:       ExitRuntimeErr,
			Retryable:      true,
			Summary:        "Missing required 'command' argument for airlock_exec.",
			RemediationCmd: "airlock run -- <command>",
			Why:            "Airlock requires an explicit command to execute inside the sandbox boundary.",
		}), nil
	}

	// 1. Resolve Command tokens
	var cmdTokens []string
	if len(args.Args) > 0 {
		cmdTokens = append([]string{args.Command}, args.Args...)
	} else {
		cmdTokens = strings.Fields(args.Command)
	}

	if len(cmdTokens) == 0 {
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_INVALID_ARGS",
			ExitCode:       ExitRuntimeErr,
			Retryable:      true,
			Summary:        "Command for airlock_exec must contain at least one executable token.",
			RemediationCmd: "airlock run -- <command>",
			Why:            "Airlock requires an explicit executable token to confine inside the sandbox.",
		}), nil
	}

	// 2. Resolve Workspace & Receipt Policy Context
	workspaceRoot := args.Workspace
	if workspaceRoot == "" {
		cwd, err := os.Getwd()
		if err == nil {
			workspaceRoot = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	sessionID := resolveSessionID(args.SessionID)
	emitReceipt := shouldEmitReceipt(args.EmitReceipt, sessionID)
	receiptDir := strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR"))

	if emitReceipt && receiptDir != "" {
		if err := ValidateReceiptDir(receiptDir, workspaceRoot); err != nil {
			return NewUBMCPErrorResult(&UBMCPError{
				Code:           "AIRLOCK_RECEIPT_POLICY_DENIED",
				ExitCode:       ExitPolicyDeny,
				Retryable:      false,
				Summary:        "Refused receipt persistence because FABRIAL_RECEIPT_DIR failed non-symlink security verification.",
				RemediationCmd: "fabrial doctor --fix",
				Why:            "Receipt directories must be real user-owned directories (O_NOFOLLOW) to prevent symlink traversal attacks.",
				DeepWhy:        err.Error(),
				References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
			}), nil
		}
	}

	// Helper to emit a BLPR-v1 receipt without ever embedding secret values.
	emitExecReceipt := func(verdict Verdict, ffCode string, exitCode int, airgapMode bool, leaseCount int) (string, error) {
		if !emitReceipt || receiptDir == "" {
			return "", nil
		}
		egressMode := "proxy_allowlist"
		if airgapMode {
			egressMode = "airgap"
		} else if args.AllowNetwork {
			egressMode = "direct_network"
		}
		rcptID, _, err := EmitReceipt(ctx, ReceiptParams{
			ReceiptDir:    receiptDir,
			WorkspaceRoot: workspaceRoot,
			SessionID:     sessionID,
			SubjectName:   cmdTokens[0],
			SubjectData:   []byte(strings.Join(cmdTokens, "\x00")),
			Verdict:       verdict,
			Claims: map[string]any{
				"tool_action":    "airlock_exec",
				"profile_mode":   config.ProfileAgent,
				"kernel_backend": kernelBackendName(),
				"egress_mode":    egressMode,
				"airgap":         airgapMode,
				"exit_code":      exitCode,
				"leases_count":   leaseCount,
			},
			FixForwardCode: ffCode,
		})
		return rcptID, err
	}

	// 3. Load Declarative Config on top of hardened 'agent' profile baseline (AIR-02 / AIR-05)
	loadedCfg, _ := config.GetBuiltinProfile(config.ProfileAgent)
	discoveredConfigPath := args.ConfigPath
	if discoveredConfigPath != "" {
		cfg, err := config.LoadFromFile(discoveredConfigPath)
		if err == nil {
			if config.IsUntrustedWorkspaceConfigPath(discoveredConfigPath, workspaceRoot) {
				loadedCfg, _ = config.AttenuateWorkspaceConfig(loadedCfg, cfg, workspaceRoot)
			} else {
				loadedCfg = config.MergeProfiles(loadedCfg, cfg)
			}
		}
	} else {
		p, cfg, _, err := config.DiscoverAndMergeConfig(loadedCfg, workspaceRoot)
		if err == nil && cfg != nil {
			loadedCfg = cfg
			discoveredConfigPath = p
		}
	}

	airgap := args.Airgap
	antiLoopback := true
	extraDomains := append([]string(nil), args.AllowDomains...)
	keptEnvVars := append([]string(nil), args.KeepEnv...)
	var deniedEnvVars []string
	var extraAllowRead []string
	var extraAllowWrite []string
	var extraDenyRead []string
	var extraDenyWrite []string
	var ignoredVetRules []string
	var allowedUnixSockets []string
	var allowedLoopbackPorts []int
	vetEnabled := true
	vetStrict := true

	if loadedCfg != nil {
		config.SanitizeAndEnforceGuardrails(loadedCfg)
		if loadedCfg.Network.Airgap && !args.AllowNetwork {
			airgap = true
		}
		if loadedCfg.Network.AntiLoopback {
			antiLoopback = true
		}
		allowedUnixSockets = append(allowedUnixSockets, loadedCfg.Network.AllowedUnixSockets...)
		allowedLoopbackPorts = append(allowedLoopbackPorts, loadedCfg.Network.AllowedLoopbackPorts...)
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

	// 3b. Redeem Opaque Secret Leases via Locksmith UDS (zero raw secrets exposed to LLM)
	var redeemed []redeemedLease
	var injectedEnv []string
	if len(args.SecretLeases) > 0 {
		lsClient := secrets.NewLocksmithClient("")
		for _, leaseID := range args.SecretLeases {
			envVar, secretBytes, cleanup, err := lsClient.RedeemOpaqueLease(ctx, leaseID, sessionID)
			if err != nil {
				rcptID, _ := emitExecReceipt(VerdictDeny, "AIRLOCK_LEASE_DENIED", ExitSecretGuardBlock, airgap, len(args.SecretLeases))
				return NewUBMCPErrorResult(&UBMCPError{
					Code:           "AIRLOCK_LEASE_DENIED",
					ExitCode:       ExitSecretGuardBlock,
					Retryable:      false,
					Summary:        "Unable to redeem opaque secret lease from local Locksmith daemon.",
					RemediationCmd: "fabrial session begin",
					Why:            "Opaque secret leases are session-bound and single-use to prevent unauthorized credential replay.",
					DeepWhy:        err.Error(),
					ReceiptID:      rcptID,
					References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
				}), nil
			}
			defer cleanup()
			redeemed = append(redeemed, redeemedLease{envVar: envVar, secret: secretBytes})
			injectedEnv = append(injectedEnv, envVar+"="+string(secretBytes))
		}
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
		WorkspaceRoot:        workspaceRoot,
		Profile:              config.ProfileAgent,
		ConfigPath:           discoveredConfigPath,
		Airgap:               airgap,
		AllowDirectNet:       args.AllowNetwork,
		AntiLoopback:         antiLoopback,
		AllowedUnixSockets:   allowedUnixSockets,
		AllowedLoopbackPorts: allowedLoopbackPorts,
		AllowedDomains:       extraDomains,
		ExtraEnv:             injectedEnv,
		KeepEnv:              keptEnvVars,
		DenyEnv:              deniedEnvVars,
		ExtraAllowRead:       extraAllowRead,
		ExtraAllowWrite:      extraAllowWrite,
		ExtraDenyRead:        extraDenyRead,
		ExtraDenyWrite:       extraDenyWrite,
		NonInteractive:       true,
		AuditLogger:          effectiveLogger,
		VetEnabled:           vetEnabled,
		VetStrict:            vetStrict,
		IgnoredVetRules:      ignoredVetRules,
		Stdout:               &stdoutBuf,
		Stderr:               &stderrBuf,
	}

	eng, err := sandbox.NewEngine(opts)
	if err != nil {
		clear(injectedEnv)
		rcptID, _ := emitExecReceipt(VerdictDeny, "AIRLOCK_SANDBOX_DENIED", ExitSandboxViolation, airgap, len(redeemed))
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_SANDBOX_DENIED",
			ExitCode:       ExitSandboxViolation,
			Retryable:      false,
			Summary:        "Failed to initialize kernel sandbox confinement engine.",
			RemediationCmd: "airlock doctor",
			Why:            "Airlock fails closed whenever OS sandbox primitives cannot be initialized.",
			DeepWhy:        err.Error(),
			ReceiptID:      rcptID,
			References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
		}), nil
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
	clear(injectedEnv)

	rawOut := stdoutBuf.Bytes()
	rawErr := stderrBuf.Bytes()
	if len(redeemed) > 0 {
		defer func() {
			clear(rawOut)
			clear(rawErr)
		}()
		// 7. Fail closed if ANY redeemed leased secret leaked into child stdout or stderr
		if leakedVar, leaked := detectLeasedSecretLeak(rawOut, rawErr, redeemed); leaked {
			clear(rawOut)
			clear(rawErr)
			rcptID, rcptErr := emitExecReceipt(VerdictDeny, "AIRLOCK_SECRET_LEAK_BLOCKED", ExitSecretGuardBlock, airgap, len(redeemed))
			if rcptErr != nil && errors.Is(rcptErr, ErrReceiptSymlinkPolicy) {
				return NewUBMCPErrorResult(&UBMCPError{
					Code:           "AIRLOCK_RECEIPT_POLICY_DENIED",
					ExitCode:       ExitPolicyDeny,
					Retryable:      false,
					Summary:        "Refused receipt persistence because FABRIAL_RECEIPT_DIR failed non-symlink verification.",
					RemediationCmd: "fabrial doctor --fix",
					Why:            "Receipt directories must be real user-owned directories (O_NOFOLLOW).",
				}), nil
			}
			return NewUBMCPErrorResult(&UBMCPError{
				Code:           "AIRLOCK_SECRET_LEAK_BLOCKED",
				ExitCode:       ExitSecretGuardBlock,
				Retryable:      false,
				Summary:        fmt.Sprintf("Blocked output from leaking leased secret for %s.", leakedVar),
				RemediationCmd: "airlock explain sandbox --why",
				Why:            "Airlock scrubs and blocks output containing leased credentials so raw secrets never enter the LLM context window.",
				ReceiptID:      rcptID,
				References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
			}), nil
		}
	}

	redactedStdout := redact.RedactString(string(rawOut))
	redactedStderr := redact.RedactString(string(rawErr))

	// 8. Classify Argus pre-exec vetting block vs. sandbox confinement violation vs. regular execution result
	if execErr != nil && strings.Contains(execErr.Error(), "Argus static analysis") {
		rcptID, _ := emitExecReceipt(VerdictDeny, "AIRLOCK_VET_BLOCKED", ExitSupplyChainBlock, airgap, len(redeemed))
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_VET_BLOCKED",
			ExitCode:       ExitSupplyChainBlock,
			Retryable:      true,
			Summary:        "Paused execution after Argus static analysis detected high-risk supply-chain or shell patterns.",
			RemediationCmd: "airlock vet --strict",
			Why:            "Pre-execution vetting blocks typosquatted packages and malicious install scripts before code runs.",
			DeepWhy:        redactedStderr,
			ReceiptID:      rcptID,
			References:     []string{"https://github.com/bonjoski/airlock/blob/main/docs/use-cases/03-preflight-policy-vetting.md"},
		}), nil
	}

	if (exitCode != 0 || execErr != nil) && isSandboxDenial(execErr, redactedStderr, redactedStdout) {
		rcptID, _ := emitExecReceipt(VerdictDeny, "AIRLOCK_SANDBOX_DENIED", ExitSandboxViolation, airgap, len(redeemed))
		detail := strings.TrimSpace(redactedStderr)
		if detail == "" && execErr != nil {
			detail = execErr.Error()
		}
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_SANDBOX_DENIED",
			ExitCode:       ExitSandboxViolation,
			Retryable:      true,
			Summary:        fmt.Sprintf("Airlock sandbox denied command '%s' due to confinement policy.", cmdTokens[0]),
			RemediationCmd: "airlock explain sandbox --why",
			Why:            "Airlock confines processes to the active workspace and allowlisted egress domains to protect host credentials.",
			DeepWhy:        detail,
			ReceiptID:      rcptID,
			References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
		}), nil
	}

	verdict := VerdictAllow
	ffCode := ""
	if exitCode != 0 || execErr != nil {
		verdict = VerdictDeny
		ffCode = "AIRLOCK_COMMAND_FAILED"
	}
	rcptID, rcptErr := emitExecReceipt(verdict, ffCode, exitCode, airgap, len(redeemed))
	if rcptErr != nil && errors.Is(rcptErr, ErrReceiptSymlinkPolicy) {
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_RECEIPT_POLICY_DENIED",
			ExitCode:       ExitPolicyDeny,
			Retryable:      false,
			Summary:        "Refused receipt persistence because FABRIAL_RECEIPT_DIR failed non-symlink verification.",
			RemediationCmd: "fabrial doctor --fix",
			Why:            "Receipt directories must be real user-owned directories (O_NOFOLLOW).",
		}), nil
	}

	res := ExecResult{
		ExitCode:       exitCode,
		Stdout:         redactedStdout,
		Stderr:         redactedStderr,
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

	callRes := &CallToolResult{
		Content: []ContentItem{{Type: "text", Text: string(resBytes)}},
		IsError: exitCode != 0 || execErr != nil,
	}
	if callRes.IsError {
		callRes.StructuredContent = SanitizeUBMCPError(&UBMCPError{
			Code:           "AIRLOCK_COMMAND_FAILED",
			ExitCode:       ExitRuntimeErr,
			Retryable:      true,
			Summary:        fmt.Sprintf("Sandboxed command '%s' exited with code %d.", cmdTokens[0], exitCode),
			RemediationCmd: "airlock doctor",
			Why:            "The confined command returned a non-zero exit status; inspect stdout/stderr for command diagnostics.",
			DeepWhy:        redactedStderr,
			ReceiptID:      rcptID,
			References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
		})
	}
	return callRes, nil
}

// VetArgs represents input arguments for airlock_vet.
type VetArgs struct {
	Command     string `json:"command,omitempty"`
	Workspace   string `json:"workspace,omitempty"`
	Strict      bool   `json:"strict,omitempty"`
	SessionID   string `json:"session_id,omitempty"`
	EmitReceipt *bool  `json:"emit_receipt,omitempty"`
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

	sessionID := resolveSessionID(args.SessionID)
	emitReceipt := shouldEmitReceipt(args.EmitReceipt, sessionID)
	receiptDir := strings.TrimSpace(os.Getenv("FABRIAL_RECEIPT_DIR"))

	if emitReceipt && receiptDir != "" {
		if err := ValidateReceiptDir(receiptDir, targetWorkspace); err != nil {
			return NewUBMCPErrorResult(&UBMCPError{
				Code:           "AIRLOCK_RECEIPT_POLICY_DENIED",
				ExitCode:       ExitPolicyDeny,
				Retryable:      false,
				Summary:        "Refused receipt persistence because FABRIAL_RECEIPT_DIR failed non-symlink security verification.",
				RemediationCmd: "fabrial doctor --fix",
				Why:            "Receipt directories must be real user-owned directories (O_NOFOLLOW) to prevent symlink traversal attacks.",
				DeepWhy:        err.Error(),
				References:     []string{"https://github.com/bonjoski/airlock/blob/main/README.md"},
			}), nil
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

	var rcptID string
	if emitReceipt && receiptDir != "" {
		verdict := VerdictAllow
		ffCode := ""
		if !passed {
			verdict = VerdictDeny
			ffCode = "AIRLOCK_VET_BLOCKED"
		}
		subjName := targetWorkspace
		if len(cmdTokens) > 0 {
			subjName = cmdTokens[0]
		}
		if subjName == "" {
			subjName = "airlock-vet"
		}
		id, _, rcptErr := EmitReceipt(ctx, ReceiptParams{
			ReceiptDir:    receiptDir,
			WorkspaceRoot: targetWorkspace,
			SessionID:     sessionID,
			SubjectName:   subjName,
			SubjectData:   []byte(args.Command + "\x00" + targetWorkspace),
			Verdict:       verdict,
			Claims: map[string]any{
				"tool_action":          "airlock_vet",
				"strict":               args.Strict,
				"total_issues":         len(findingsList),
				"high_critical_issues": highCriticalCount,
			},
			FixForwardCode: ffCode,
		})
		if rcptErr != nil && errors.Is(rcptErr, ErrReceiptSymlinkPolicy) {
			return NewUBMCPErrorResult(&UBMCPError{
				Code:           "AIRLOCK_RECEIPT_POLICY_DENIED",
				ExitCode:       ExitPolicyDeny,
				Retryable:      false,
				Summary:        "Refused receipt persistence because FABRIAL_RECEIPT_DIR failed non-symlink verification.",
				RemediationCmd: "fabrial doctor --fix",
				Why:            "Receipt directories must be real user-owned directories (O_NOFOLLOW).",
			}), nil
		}
		rcptID = id
	}

	if !passed {
		var detailLines []string
		for _, f := range findingsList {
			detailLines = append(detailLines, fmt.Sprintf("[%s] %s: %s", f.Severity, f.RuleID, f.Description))
		}
		return NewUBMCPErrorResult(&UBMCPError{
			Code:           "AIRLOCK_VET_BLOCKED",
			ExitCode:       ExitSupplyChainBlock,
			Retryable:      true,
			Summary:        summary,
			RemediationCmd: "airlock vet --strict",
			Why:            "Pre-execution static analysis blocks typosquatted packages and malicious install hooks before execution.",
			DeepWhy:        strings.Join(detailLines, "\n"),
			SelfHeal: &SelfHealHint{
				SuggestedTool:         "airlock_vet",
				SuggestedArgs:         map[string]any{"strict": true},
				RequiresHumanApproval: true,
			},
			ReceiptID:  rcptID,
			References: []string{"https://github.com/bonjoski/airlock/blob/main/docs/use-cases/03-preflight-policy-vetting.md"},
		}), nil
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
		IsError: false,
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
		isForbidden := config.IsForbiddenPath(targetPath)
		forbiddenReason := ""
		if isForbidden {
			forbiddenReason = "Strictly blocked by Airlock Guardrail: sensitive secret or restricted system path."
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
		forbidden := config.IsForbiddenEnv(envVar) || envVar == "DYLD_LIBRARY_PATH"
		reason := "Permitted if present in allowlist"
		if forbidden {
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
