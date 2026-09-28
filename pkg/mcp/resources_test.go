package mcp

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/airlock/pkg/audit"
)

func TestMCPResources_List(t *testing.T) {
	handler := NewDefaultResourceHandler()
	res, err := handler.ListResources(context.Background())
	if err != nil {
		t.Fatalf("ListResources failed: %v", err)
	}

	if len(res.Resources) != 3 {
		t.Fatalf("Expected 3 resources, got %d", len(res.Resources))
	}

	uris := make(map[string]bool)
	for _, r := range res.Resources {
		uris[r.URI] = true
		if r.MIMEType != "application/json" {
			t.Errorf("Expected MIMEType 'application/json' for %s, got %s", r.URI, r.MIMEType)
		}
	}

	if !uris[ResourceURIAuditRecent] {
		t.Errorf("Missing resource: %s", ResourceURIAuditRecent)
	}
	if !uris[ResourceURIPolicyActive] {
		t.Errorf("Missing resource: %s", ResourceURIPolicyActive)
	}
	if !uris[ResourceURIHealth] {
		t.Errorf("Missing resource: %s", ResourceURIHealth)
	}
}

func TestMCPResources_Read_AuditRecent_Empty(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentLog := filepath.Join(tempDir, "audit.log")

	handler := NewDefaultResourceHandler(WithResourceAuditLog(nonExistentLog))
	res, err := handler.ReadResource(context.Background(), ResourceURIAuditRecent)
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	if len(res.Contents) != 1 {
		t.Fatalf("Expected 1 content item, got %d", len(res.Contents))
	}

	var records []map[string]interface{}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &records); err != nil {
		t.Fatalf("Failed to parse returned audit records: %v", err)
	}
	if len(records) != 0 {
		t.Errorf("Expected 0 audit records, got %d", len(records))
	}
}

func TestMCPResources_Read_AuditRecent_WithEntries(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	logger := audit.NewFileLogger(nil)
	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}
	logger = audit.NewFileLogger(f)

	_ = logger.LogExecution(audit.ExecutionRecord{
		Command:       "npm",
		Args:          []string{"install"},
		WorkspaceRoot: tempDir,
		Airgap:        false,
		ExitCode:      0,
	})
	_ = logger.LogSecurity(audit.SecurityRecord{
		Category: "FILE_RESTRICTION",
		Details:  "Attempted access to ~/.ssh/id_rsa blocked by invariant",
	})
	_ = logger.Close()

	handler := NewDefaultResourceHandler(WithResourceAuditLog(logPath))
	res, err := handler.ReadResource(context.Background(), ResourceURIAuditRecent)
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	var records []map[string]interface{}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &records); err != nil {
		t.Fatalf("Failed to parse returned audit records: %v\nPayload: %s", err, res.Contents[0].Text)
	}

	if len(records) != 2 {
		t.Fatalf("Expected 2 audit records, got %d", len(records))
	}

	if records[0]["type"] != string(audit.EventExecution) {
		t.Errorf("Expected first record type 'execution', got %v", records[0]["type"])
	}
	if records[1]["type"] != string(audit.EventSecurityViolation) {
		t.Errorf("Expected second record type 'security_violation', got %v", records[1]["type"])
	}
}

func TestMCPResources_Read_PolicyActive(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "airlock.yaml")
	cfgData := `version: "1"
mode: "strict"
network:
  airgap: true
filesystem:
  allow_read:
    - "~/.ssh/id_rsa"
env:
  allow:
    - "LD_PRELOAD"
`
	if err := os.WriteFile(cfgPath, []byte(cfgData), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	handler := NewDefaultResourceHandler(WithResourceWorkspace(tempDir))
	res, err := handler.ReadResource(context.Background(), ResourceURIPolicyActive)
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	var policyData map[string]interface{}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &policyData); err != nil {
		t.Fatalf("Failed to unmarshal policy data: %v", err)
	}

	if policyData["config_found"] != true {
		t.Errorf("Expected config_found=true")
	}

	invariants, ok := policyData["immutable_invariants"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected immutable_invariants map in policy resource")
	}
	forbiddenPaths, ok := invariants["forbidden_paths"].([]interface{})
	if !ok || len(forbiddenPaths) == 0 {
		t.Errorf("Expected forbidden_paths in immutable invariants")
	}

	warnings, ok := policyData["guardrail_warnings"].([]interface{})
	if !ok || len(warnings) < 2 {
		t.Errorf("Expected at least 2 guardrail warnings for ~/.ssh and LD_PRELOAD, got %d", len(warnings))
	}
}

func TestMCPResources_Read_Health(t *testing.T) {
	handler := NewDefaultResourceHandler()
	res, err := handler.ReadResource(context.Background(), ResourceURIHealth)
	if err != nil {
		t.Fatalf("ReadResource failed: %v", err)
	}

	var healthData map[string]interface{}
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &healthData); err != nil {
		t.Fatalf("Failed to unmarshal health data: %v", err)
	}

	if healthData["status"] != "healthy" {
		t.Errorf("Expected status 'healthy', got %v", healthData["status"])
	}

	caps, ok := healthData["isolation_capabilities"].(map[string]interface{})
	if !ok {
		t.Fatalf("Expected isolation_capabilities in health data")
	}
	if caps["network_egress_proxy"] != true {
		t.Errorf("Expected network_egress_proxy to be true")
	}
	if caps["environment_sanitization"] != true {
		t.Errorf("Expected environment_sanitization to be true")
	}
}

func TestMCPResources_Read_UnknownURI(t *testing.T) {
	handler := NewDefaultResourceHandler()
	_, err := handler.ReadResource(context.Background(), "airlock://unknown/resource")
	if err == nil {
		t.Fatalf("Expected error for unknown URI, got nil")
	}
}
