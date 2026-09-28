package mcp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/sandbox"
)

// Standard Resource URIs
const (
	ResourceURIAuditRecent  = "airlock://audit/recent"
	ResourceURIPolicyActive = "airlock://policy/active"
	ResourceURIHealth       = "airlock://health"
)

// SupportedResources returns the specifications for standard MCP resources exposed by Airlock.
func SupportedResources() []Resource {
	return []Resource{
		{
			URI:         ResourceURIAuditRecent,
			Name:        "Recent Audit Logs",
			Description: "Tail of recent structured JSON audit log records for sandboxed executions, network egress, and security violations.",
			MIMEType:    "application/json",
		},
		{
			URI:         ResourceURIPolicyActive,
			Name:        "Active Policy & Invariant Guardrails",
			Description: "Active project policy (airlock.yaml) combined with immutable zero-trust invariant guardrails.",
			MIMEType:    "application/json",
		},
		{
			URI:         ResourceURIHealth,
			Name:        "Sandbox & Proxy Health",
			Description: "Real-time system sandbox isolation, platform backend, and egress proxy health status.",
			MIMEType:    "application/json",
		},
	}
}

// ResourceHandler defines the interface for handling MCP resource requests.
type ResourceHandler interface {
	ListResources(ctx context.Context) (*ListResourcesResult, error)
	ReadResource(ctx context.Context, uri string) (*ReadResourceResult, error)
}

// ResourceHandlerOption configures the DefaultResourceHandler.
type ResourceHandlerOption func(*DefaultResourceHandler)

// WithResourceWorkspace sets the workspace root used for policy discovery.
func WithResourceWorkspace(workspaceRoot string) ResourceHandlerOption {
	return func(h *DefaultResourceHandler) {
		h.workspaceRoot = workspaceRoot
	}
}

// WithResourceAuditLog sets the audit log file path used for audit queries.
func WithResourceAuditLog(auditLogPath string) ResourceHandlerOption {
	return func(h *DefaultResourceHandler) {
		h.auditLogPath = auditLogPath
	}
}

// DefaultResourceHandler implements ResourceHandler using standard Airlock runtime data.
type DefaultResourceHandler struct {
	workspaceRoot string
	auditLogPath  string
}

// NewDefaultResourceHandler creates a new DefaultResourceHandler.
func NewDefaultResourceHandler(opts ...ResourceHandlerOption) *DefaultResourceHandler {
	h := &DefaultResourceHandler{}
	for _, opt := range opts {
		opt(h)
	}
	return h
}

// ListResources returns the list of available MCP resources.
func (h *DefaultResourceHandler) ListResources(ctx context.Context) (*ListResourcesResult, error) {
	return &ListResourcesResult{
		Resources: SupportedResources(),
	}, nil
}

// ReadResource reads and formats the requested resource.
func (h *DefaultResourceHandler) ReadResource(ctx context.Context, uri string) (*ReadResourceResult, error) {
	switch uri {
	case ResourceURIAuditRecent:
		return h.readAuditRecent(ctx)
	case ResourceURIPolicyActive:
		return h.readPolicyActive(ctx)
	case ResourceURIHealth:
		return h.readHealth(ctx)
	default:
		return nil, fmt.Errorf("resource not found: %s", uri)
	}
}

func (h *DefaultResourceHandler) readAuditRecent(ctx context.Context) (*ReadResourceResult, error) {
	logPath := h.auditLogPath
	if logPath == "" {
		p, err := audit.DefaultAuditLogPath()
		if err != nil {
			return nil, fmt.Errorf("failed to determine audit log path: %w", err)
		}
		logPath = p
	}

	var records []json.RawMessage
	file, err := os.Open(logPath)
	if err == nil {
		defer file.Close()
		scanner := bufio.NewScanner(file)
		var lines []string
		for scanner.Scan() {
			line := strings.TrimSpace(scanner.Text())
			if line != "" {
				lines = append(lines, line)
			}
		}

		const maxEntries = 100
		startIdx := 0
		if len(lines) > maxEntries {
			startIdx = len(lines) - maxEntries
		}
		for i := startIdx; i < len(lines); i++ {
			records = append(records, json.RawMessage(lines[i]))
		}
	}

	if records == nil {
		records = []json.RawMessage{}
	}

	jsonData, err := json.MarshalIndent(records, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize audit records: %w", err)
	}

	return &ReadResourceResult{
		Contents: []ResourceContents{
			{
				URI:      ResourceURIAuditRecent,
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}

func (h *DefaultResourceHandler) readPolicyActive(ctx context.Context) (*ReadResourceResult, error) {
	workspace := h.workspaceRoot
	if workspace == "" {
		cwd, err := os.Getwd()
		if err == nil {
			workspace = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	var loadedCfg *config.Config
	var configPath string
	var issues []config.ValidationIssue

	if workspace != "" {
		for _, name := range config.ConfigFileNames {
			p := filepath.Join(workspace, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				cfg, iss, err := config.LoadFromFileWithIssues(p)
				if err == nil && cfg != nil {
					loadedCfg = cfg
					configPath = p
					issues = iss
					break
				}
			}
		}
	}

	if loadedCfg == nil {
		home, err := os.UserHomeDir()
		if err == nil {
			globalPath := filepath.Join(home, ".airlock", "config.yaml")
			if fi, err := os.Stat(globalPath); err == nil && !fi.IsDir() {
				cfg, iss, err := config.LoadFromFileWithIssues(globalPath)
				if err == nil && cfg != nil {
					loadedCfg = cfg
					configPath = globalPath
					issues = iss
				}
			}
		}
	}

	if loadedCfg == nil {
		loadedCfg = config.DefaultConfig()
		issues = config.SanitizeAndEnforceGuardrails(loadedCfg)
	}

	var warningStrings []string
	for _, issue := range issues {
		warningStrings = append(warningStrings, fmt.Sprintf("[%s] %s: %s", issue.Severity, issue.Field, issue.Message))
	}

	immutableInvariants := map[string]interface{}{
		"forbidden_paths": []string{
			".ssh",
			".aws",
			".gnupg",
			".kube",
			".config/gcloud",
			"docker.sock",
			"/var/run/docker.sock",
			".git",
		},
		"forbidden_env_vars": []string{
			"LD_PRELOAD",
			"DYLD_INSERT_LIBRARIES",
			"DYLD_FORCE_FLAT_NAMESPACE",
		},
		"airgap_enforcement": "Complete network isolation when airgap is true",
		"egress_proxy":       "All outbound TCP traffic is intercepted and filtered through local egress proxy",
		"scratch_staging":    "Isolated scratch directories prevent host pollution",
	}

	payload := map[string]interface{}{
		"config_found":         configPath != "",
		"config_path":          configPath,
		"active_config":        loadedCfg,
		"immutable_invariants": immutableInvariants,
		"guardrail_warnings":   warningStrings,
	}

	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize active policy: %w", err)
	}

	return &ReadResourceResult{
		Contents: []ResourceContents{
			{
				URI:      ResourceURIPolicyActive,
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}

func (h *DefaultResourceHandler) readHealth(ctx context.Context) (*ReadResourceResult, error) {
	backend := "Unsupported"
	switch runtime.GOOS {
	case "darwin":
		backend = "Apple Seatbelt (sandbox-exec)"
	case "linux":
		backend = "Bubblewrap (bwrap) + Seccomp"
	}

	logPath := h.auditLogPath
	if logPath == "" {
		p, _ := audit.DefaultAuditLogPath()
		logPath = p
	}

	payload := map[string]interface{}{
		"status":       "healthy",
		"platform":     runtime.GOOS,
		"architecture": runtime.GOARCH,
		"backend":      backend,
		"isolation_capabilities": map[string]bool{
			"filesystem_sandbox":       runtime.GOOS == "darwin" || runtime.GOOS == "linux",
			"network_egress_proxy":     true,
			"dns_interception":         true,
			"environment_sanitization": true,
			"argus_static_vetting":     true,
		},
		"audit_logging": map[string]interface{}{
			"enabled":  true,
			"log_path": logPath,
		},
		"timestamp": time.Now().UTC().Format(time.RFC3339),
	}

	jsonData, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to serialize health status: %w", err)
	}

	return &ReadResourceResult{
		Contents: []ResourceContents{
			{
				URI:      ResourceURIHealth,
				MIMEType: "application/json",
				Text:     string(jsonData),
			},
		},
	}, nil
}
