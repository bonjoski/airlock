package mcp

import (
	"context"
	"fmt"
	"strings"
)

const (
	PromptSecurityReview      = "security_review"
	PromptPreInstallAudit     = "pre_install_audit"
	PromptSandboxTroubleshoot = "sandbox_troubleshoot"
)

// PromptHandler defines the interface for MCP prompt operations.
type PromptHandler interface {
	ListPrompts(ctx context.Context) (*ListPromptsResult, error)
	GetPrompt(ctx context.Context, name string, args map[string]string) (*GetPromptResult, error)
}

// PromptHandlerOption customizes DefaultPromptHandler.
type PromptHandlerOption func(*DefaultPromptHandler)

// DefaultPromptHandler implements PromptHandler.
type DefaultPromptHandler struct{}

// NewDefaultPromptHandler creates a new DefaultPromptHandler.
func NewDefaultPromptHandler(opts ...PromptHandlerOption) *DefaultPromptHandler {
	h := &DefaultPromptHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ListPrompts returns the available MCP prompts.
func (h *DefaultPromptHandler) ListPrompts(ctx context.Context) (*ListPromptsResult, error) {
	return &ListPromptsResult{
		Prompts: []Prompt{
			{
				Name:        PromptSecurityReview,
				Description: "Instructs the AI assistant to perform a comprehensive security review on target source code or configuration files using Airlock vetting tools.",
				Arguments: []PromptArgument{
					{
						Name:        "target_path",
						Description: "Path to the file or directory to inspect (e.g. 'src/auth/jwt.go', 'package.json')",
						Required:    true,
					},
					{
						Name:        "context",
						Description: "Context or rationale for the code modification or security check",
						Required:    false,
					},
				},
			},
			{
				Name:        PromptPreInstallAudit,
				Description: "Instructs the AI assistant to audit third-party packages for typosquatting and malicious lifecycle scripts before installation.",
				Arguments: []PromptArgument{
					{
						Name:        "package_name",
						Description: "The name of the package to audit (e.g. 'event-stream', 'crossenv')",
						Required:    true,
					},
					{
						Name:        "ecosystem",
						Description: "Package manager ecosystem: npm, pnpm, yarn, pip, cargo, uv, or bun",
						Required:    false,
					},
					{
						Name:        "version",
						Description: "Target version string if known",
						Required:    false,
					},
				},
			},
			{
				Name:        PromptSandboxTroubleshoot,
				Description: "Assists in diagnosing and troubleshooting sandboxing denials, network proxy blocks, or environment variable issues.",
				Arguments: []PromptArgument{
					{
						Name:        "error_message",
						Description: "The error message or failure log observed during execution",
						Required:    true,
					},
					{
						Name:        "command",
						Description: "The command line that produced the failure",
						Required:    false,
					},
					{
						Name:        "domain",
						Description: "Target network domain if the error involves DNS or network egress denial",
						Required:    false,
					},
				},
			},
		},
	}, nil
}

// GetPrompt returns a prompt template populated with the provided arguments.
func (h *DefaultPromptHandler) GetPrompt(ctx context.Context, name string, args map[string]string) (*GetPromptResult, error) {
	switch name {
	case PromptSecurityReview:
		targetPath := strings.TrimSpace(args["target_path"])
		if targetPath == "" {
			return nil, fmt.Errorf("missing required argument 'target_path'")
		}
		userContext := strings.TrimSpace(args["context"])

		text := fmt.Sprintf(
			"You are an AI security auditor evaluating %s.\n\n"+
				"Target File / Directory: %s\n"+
				"Context: %s\n\n"+
				"Security Guidelines:\n"+
				"1. Use 'airlock_vet' to scan for suspicious lifecycle hooks, obfuscated payloads, or network exfiltration logic.\n"+
				"2. Verify that credentials, secrets (.env), and .git hooks are protected and cannot be leaked.\n"+
				"3. Ensure any execution is conducted inside the Airlock sandbox ('airlock_exec').\n"+
				"4. Summarize all findings and recommend fixes.",
			targetPath, targetPath, userContext,
		)

		return &GetPromptResult{
			Description: fmt.Sprintf("Security review for %s", targetPath),
			Messages: []PromptMessage{
				{
					Role: RoleUser,
					Content: ContentItem{
						Type: "text",
						Text: text,
					},
				},
			},
		}, nil

	case PromptPreInstallAudit:
		pkgName := strings.TrimSpace(args["package_name"])
		if pkgName == "" {
			return nil, fmt.Errorf("missing required argument 'package_name'")
		}
		ecosystem := strings.TrimSpace(args["ecosystem"])
		if ecosystem == "" {
			ecosystem = "npm"
		}
		version := strings.TrimSpace(args["version"])

		text := fmt.Sprintf(
			"You are an AI assistant performing a pre-install audit for package %q (%s, version: %s).\n\n"+
				"Audit Instructions:\n"+
				"1. Use 'airlock_vet' to inspect the package installation command for typosquatting (e.g. 'crossenv', 'reqeusts') and manifest lifecycle risks.\n"+
				"2. Check if the package requires external network egress during build/install and verify compliance using 'airlock_policy_check'.\n"+
				"3. If safe, execute the installation via 'airlock_exec'.\n"+
				"4. If suspicious or high-risk findings occur, immediately block execution and alert the user.",
			pkgName, ecosystem, version,
		)

		return &GetPromptResult{
			Description: fmt.Sprintf("Pre-installation supply-chain audit for %s (%s)", pkgName, ecosystem),
			Messages: []PromptMessage{
				{
					Role: RoleUser,
					Content: ContentItem{
						Type: "text",
						Text: text,
					},
				},
			},
		}, nil

	case PromptSandboxTroubleshoot:
		errMsg := strings.TrimSpace(args["error_message"])
		if errMsg == "" {
			return nil, fmt.Errorf("missing required argument 'error_message'")
		}
		cmd := strings.TrimSpace(args["command"])
		domain := strings.TrimSpace(args["domain"])

		text := fmt.Sprintf(
			"You are an AI assistant troubleshooting an Airlock sandbox error.\n\n"+
				"Observed Error: %s\n"+
				"Failed Command: %s\n"+
				"Target Domain: %s\n\n"+
				"Troubleshooting Steps:\n"+
				"1. Inspect recent audit logs by reading the 'airlock://audit/recent' MCP resource.\n"+
				"2. If a network domain was blocked by the fail-closed egress proxy, check whether the domain is a legitimate registry using 'airlock_policy_check'.\n"+
				"3. If a filesystem operation failed with EPERM, check if it targeted a protected invariant (~/.ssh, .git/hooks, .env).\n"+
				"4. Provide a clear diagnosis and suggest necessary declarative policy rules (airlock.yaml) or CLI flags (--allow-domain).",
			errMsg, cmd, domain,
		)

		return &GetPromptResult{
			Description: "Troubleshooting guide for Airlock sandbox denial or error",
			Messages: []PromptMessage{
				{
					Role: RoleUser,
					Content: ContentItem{
						Type: "text",
						Text: text,
					},
				},
			},
		}, nil

	default:
		return nil, fmt.Errorf("unknown prompt name: %s", name)
	}
}
