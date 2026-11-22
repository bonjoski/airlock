package mcp

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/bonjoski/airlock/pkg/ux"
)

// JSON-RPC 2.0 Standard Types

// Request represents a JSON-RPC 2.0 request or notification.
type Request struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Method  string          `json:"method"`
	Params  json.RawMessage `json:"params,omitempty"`
}

// Response represents a JSON-RPC 2.0 response.
type Response struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      json.RawMessage `json:"id,omitempty"`
	Result  interface{}     `json:"result,omitempty"`
	Error   *RPCError       `json:"error,omitempty"`
}

// RPCError represents a JSON-RPC 2.0 error object.
type RPCError struct {
	Code    int         `json:"code"`
	Message string      `json:"message"`
	Data    interface{} `json:"data,omitempty"`
}

// Standard JSON-RPC 2.0 Error Codes
const (
	CodeParseError     = -32700
	CodeInvalidRequest = -32600
	CodeMethodNotFound = -32601
	CodeInvalidParams  = -32602
	CodeInternalError  = -32603
)

// MCP Protocol Types

// ServerInfo contains metadata about the MCP server implementation.
type ServerInfo struct {
	Name    string `json:"name"`
	Version string `json:"version"`
}

// ServerCapabilities describes capabilities supported by the server.
type ServerCapabilities struct {
	Tools     *ToolsCapability     `json:"tools,omitempty"`
	Resources *ResourcesCapability `json:"resources,omitempty"`
	Prompts   *PromptsCapability   `json:"prompts,omitempty"`
	Logging   *LoggingCapability   `json:"logging,omitempty"`
}

// ToolsCapability indicates support for tools.
type ToolsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// ResourcesCapability indicates support for resources.
type ResourcesCapability struct {
	Subscribe   bool `json:"subscribe,omitempty"`
	ListChanged bool `json:"listChanged,omitempty"`
}

// PromptsCapability indicates support for prompts.
type PromptsCapability struct {
	ListChanged bool `json:"listChanged,omitempty"`
}

// LoggingCapability indicates support for logging.
type LoggingCapability struct{}

// InitializeResult is the response payload for the "initialize" method.
type InitializeResult struct {
	ProtocolVersion string             `json:"protocolVersion"`
	Capabilities    ServerCapabilities `json:"capabilities"`
	ServerInfo      ServerInfo         `json:"serverInfo"`
}

// Resource represents an MCP Resource definition.
type Resource struct {
	URI         string `json:"uri"`
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	MIMEType    string `json:"mimeType,omitempty"`
}

// ListResourcesResult is the response payload for "resources/list".
type ListResourcesResult struct {
	Resources []Resource `json:"resources"`
}

// ReadResourceParams is the parameters payload for "resources/read".
type ReadResourceParams struct {
	URI string `json:"uri"`
}

// ResourceContents represents a single resource's content.
type ResourceContents struct {
	URI      string `json:"uri"`
	MIMEType string `json:"mimeType,omitempty"`
	Text     string `json:"text,omitempty"`
	Blob     string `json:"blob,omitempty"`
}

// ReadResourceResult is the response payload for "resources/read".
type ReadResourceResult struct {
	Contents []ResourceContents `json:"contents"`
}

// PromptArgument represents an argument accepted by a prompt template.
type PromptArgument struct {
	Name        string `json:"name"`
	Description string `json:"description,omitempty"`
	Required    bool   `json:"required,omitempty"`
}

// Prompt represents an MCP Prompt definition.
type Prompt struct {
	Name        string           `json:"name"`
	Description string           `json:"description,omitempty"`
	Arguments   []PromptArgument `json:"arguments,omitempty"`
}

// ListPromptsResult is the response payload for "prompts/list".
type ListPromptsResult struct {
	Prompts []Prompt `json:"prompts"`
}

// GetPromptParams is the parameters payload for "prompts/get".
type GetPromptParams struct {
	Name      string            `json:"name"`
	Arguments map[string]string `json:"arguments,omitempty"`
}

// PromptMessageRole defines the role in a prompt message.
type PromptMessageRole string

const (
	RoleUser      PromptMessageRole = "user"
	RoleAssistant PromptMessageRole = "assistant"
)

// PromptMessage represents a message in a prompt response.
type PromptMessage struct {
	Role    PromptMessageRole `json:"role"`
	Content ContentItem       `json:"content"`
}

// GetPromptResult is the response payload for "prompts/get".
type GetPromptResult struct {
	Description string          `json:"description,omitempty"`
	Messages    []PromptMessage `json:"messages"`
}

// Tool represents an MCP Tool definition.
type Tool struct {
	Name        string      `json:"name"`
	Description string      `json:"description"`
	InputSchema InputSchema `json:"inputSchema"`
}

// InputSchema represents the JSON schema for tool arguments.
type InputSchema struct {
	Type       string                 `json:"type"`
	Properties map[string]PropertyDef `json:"properties,omitempty"`
	Required   []string               `json:"required,omitempty"`
}

// PropertyDef represents a single property in a JSON schema.
type PropertyDef struct {
	Type        string                 `json:"type"`
	Description string                 `json:"description"`
	Items       map[string]interface{} `json:"items,omitempty"`
	Default     interface{}            `json:"default,omitempty"`
}

// ListToolsResult is the response payload for "tools/list".
type ListToolsResult struct {
	Tools []Tool `json:"tools"`
}

// CallToolParams is the parameters payload for "tools/call".
type CallToolParams struct {
	Name      string          `json:"name"`
	Arguments json.RawMessage `json:"arguments"`
}

// ContentItem represents a content piece in an MCP Tool result.
type ContentItem struct {
	Type string `json:"type"`
	Text string `json:"text"`
}

// CallToolResult is the response payload for "tools/call".
type CallToolResult struct {
	Content           []ContentItem `json:"content"`
	IsError           bool          `json:"isError,omitempty"`
	StructuredContent any           `json:"structuredContent,omitempty"`
}

// UB-MCP-v1 deterministic exit code contract (RFC-2026-11-22-49).
const (
	UBMCPv1SchemaVersion = "ub-cli-v2"

	ExitOK                = 0
	ExitRuntimeErr        = 1
	ExitPolicyDeny        = 10
	ExitSupplyChainBlock  = 20
	ExitSandboxViolation  = 30
	ExitSecretGuardBlock  = 40
	ExitBiometricRequired = 82
)

// SelfHealHint provides a machine-actionable, allowlist-constrained recovery suggestion.
type SelfHealHint struct {
	SuggestedTool         string         `json:"suggested_tool"`
	SuggestedArgs         map[string]any `json:"suggested_args"`
	RequiresHumanApproval bool           `json:"requires_human_approval"`
}

// UBMCPError conforms strictly to docs/schemas/ub-mcp-v1-error.schema.json.
type UBMCPError struct {
	SchemaVersion  string        `json:"schema_version"`
	Tool           string        `json:"tool"`
	Code           string        `json:"code"`
	ExitCode       int           `json:"exit_code"`
	Retryable      bool          `json:"retryable"`
	Summary        string        `json:"summary"`
	RemediationCmd string        `json:"remediation_cmd"`
	Why            string        `json:"why"`
	DeepWhy        string        `json:"deep_why,omitempty"`
	SelfHeal       *SelfHealHint `json:"self_heal,omitempty"`
	ReceiptID      string        `json:"receipt_id,omitempty"`
	References     []string      `json:"references,omitempty"`
}

// SanitizeUBMCPError normalizes and ANSI-strips a UBMCPError so it strictly satisfies
// ub-mcp-v1-error.schema.json field bounds and terminal safety invariants.
func SanitizeUBMCPError(in *UBMCPError) *UBMCPError {
	if in == nil {
		return nil
	}
	out := &UBMCPError{
		SchemaVersion:  UBMCPv1SchemaVersion,
		Tool:           "airlock",
		Code:           sanitizeCode(in.Code),
		ExitCode:       normalizeExitCode(in.ExitCode),
		Retryable:      in.Retryable,
		Summary:        truncateRunes(sanitizeSingleLineMCP(in.Summary), 240),
		RemediationCmd: truncateRunes(sanitizeSingleLineMCP(in.RemediationCmd), 256),
		Why:            truncateRunes(sanitizeSingleLineMCP(in.Why), 280),
		DeepWhy:        truncateRunes(strings.TrimSpace(ux.SanitizeTerminalText(strings.ToValidUTF8(in.DeepWhy, ""))), 2048),
		ReceiptID:      sanitizeSingleLineMCP(in.ReceiptID),
	}
	if out.Summary == "" {
		out.Summary = "Airlock paused execution due to a security or runtime policy violation."
	}
	if out.RemediationCmd == "" {
		out.RemediationCmd = "airlock explain sandbox --why"
	}
	if out.Why == "" {
		out.Why = "Airlock enforces default-deny kernel confinement and secret isolation on the local workstation."
	}
	if in.SelfHeal != nil && in.SelfHeal.SuggestedTool != "" {
		cleanArgs := make(map[string]any, len(in.SelfHeal.SuggestedArgs))
		for k, v := range in.SelfHeal.SuggestedArgs {
			ck := sanitizeSingleLineMCP(k)
			if ck == "" {
				continue
			}
			switch tv := v.(type) {
			case string:
				cleanArgs[ck] = sanitizeSingleLineMCP(tv)
			default:
				cleanArgs[ck] = tv
			}
		}
		out.SelfHeal = &SelfHealHint{
			SuggestedTool:         sanitizeSingleLineMCP(in.SelfHeal.SuggestedTool),
			SuggestedArgs:         cleanArgs,
			RequiresHumanApproval: in.SelfHeal.RequiresHumanApproval,
		}
	}
	for _, ref := range in.References {
		cleanRef := sanitizeSingleLineMCP(ref)
		if strings.HasPrefix(cleanRef, "https://") || strings.HasPrefix(cleanRef, "http://") {
			out.References = append(out.References, cleanRef)
		}
	}
	if out.ReceiptID != "" && !strings.HasPrefix(out.ReceiptID, "rcpt_") {
		out.ReceiptID = ""
	}
	return out
}

// FormatCalmErrorText renders a UBMCPError into calm <=3-line human text.
func FormatCalmErrorText(e *UBMCPError) string {
	s := SanitizeUBMCPError(e)
	if s == nil {
		return "⚠ airlock: execution paused"
	}
	return fmt.Sprintf("⚠ %s: %s\n  Fix:  %s\n  Why:  %s", s.Tool, s.Summary, s.RemediationCmd, s.Why)
}

// NewUBMCPErrorResult constructs an MCP CallToolResult with IsError=true,
// calm <=3-line human text in Content[0].Text, and a schema-compliant UBMCPError
// in StructuredContent.
func NewUBMCPErrorResult(e *UBMCPError) *CallToolResult {
	sanitized := SanitizeUBMCPError(e)
	return &CallToolResult{
		Content:           []ContentItem{{Type: "text", Text: FormatCalmErrorText(sanitized)}},
		IsError:           true,
		StructuredContent: sanitized,
	}
}

func sanitizeSingleLineMCP(s string) string {
	clean := ux.SanitizeTerminalText(strings.ToValidUTF8(s, ""))
	clean = strings.ReplaceAll(clean, "\r", " ")
	clean = strings.ReplaceAll(clean, "\n", " ")
	clean = strings.ReplaceAll(clean, "\t", " ")
	return strings.TrimSpace(clean)
}

func truncateRunes(s string, max int) string {
	r := []rune(s)
	if len(r) <= max {
		return s
	}
	if max <= 3 {
		return string(r[:max])
	}
	return string(r[:max-3]) + "..."
}

func sanitizeCode(code string) string {
	clean := strings.ToUpper(sanitizeSingleLineMCP(code))
	var b strings.Builder
	for _, r := range clean {
		if (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' {
			b.WriteRune(r)
		}
	}
	res := b.String()
	if len(res) < 3 || res[0] < 'A' || res[0] > 'Z' {
		return "AIRLOCK_ERROR"
	}
	if len(res) > 64 {
		res = res[:64]
	}
	return res
}

func normalizeExitCode(code int) int {
	switch code {
	case ExitRuntimeErr, ExitPolicyDeny, ExitSupplyChainBlock, ExitSandboxViolation, ExitSecretGuardBlock, ExitBiometricRequired:
		return code
	default:
		return ExitRuntimeErr
	}
}
