package tests

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/mcp"
)

// TestSEC30_MCPExtensions verifies MCP resources and prompts protocol compliance,
// immutable security invariant enforcement via resources, audit log tailing,
// prompt templates, and JSON-RPC 2.0 error envelopes (SEC-30).
func TestSEC30_MCPExtensions(t *testing.T) {
	ctx := context.Background()

	t.Run("CapabilityDeclarationHandshake", func(t *testing.T) {
		server := mcp.NewServer(nil, nil, mcp.WithVersion("1.1.0"))
		initReq := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`

		resp, err := server.HandleMessage(ctx, []byte(initReq))
		if err != nil {
			t.Fatalf("SEC-30 FAILED: HandleMessage error on initialize: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("SEC-30 FAILED: Unexpected RPC error on initialize: %+v", resp.Error)
		}

		result, ok := resp.Result.(mcp.InitializeResult)
		if !ok {
			t.Fatalf("SEC-30 FAILED: Expected InitializeResult, got %T", resp.Result)
		}

		if result.ServerInfo.Name != "airlock-mcp" {
			t.Errorf("SEC-30 FAILED: Expected server name 'airlock-mcp', got %q", result.ServerInfo.Name)
		}

		// Verify all four standard MCP capabilities are declared
		if result.Capabilities.Tools == nil {
			t.Errorf("SEC-30 FAILED: Tools capability must be declared")
		}
		if result.Capabilities.Resources == nil {
			t.Errorf("SEC-30 FAILED: Resources capability must be declared")
		}
		if result.Capabilities.Prompts == nil {
			t.Errorf("SEC-30 FAILED: Prompts capability must be declared")
		}
		if result.Capabilities.Logging == nil {
			t.Errorf("SEC-30 FAILED: Logging capability must be declared")
		}
	})

	t.Run("Resources_ListAndStandardURIs", func(t *testing.T) {
		server := mcp.NewServer(nil, nil)
		listReq := `{"jsonrpc":"2.0","id":2,"method":"resources/list"}`

		resp, err := server.HandleMessage(ctx, []byte(listReq))
		if err != nil {
			t.Fatalf("SEC-30 FAILED: resources/list error: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("SEC-30 FAILED: resources/list returned RPC error: %+v", resp.Error)
		}

		result, ok := resp.Result.(*mcp.ListResourcesResult)
		if !ok {
			t.Fatalf("SEC-30 FAILED: Expected *ListResourcesResult, got %T", resp.Result)
		}

		expectedURIs := map[string]bool{
			mcp.ResourceURIAuditRecent:  false,
			mcp.ResourceURIPolicyActive: false,
			mcp.ResourceURIHealth:       false,
		}

		for _, res := range result.Resources {
			if _, exists := expectedURIs[res.URI]; exists {
				expectedURIs[res.URI] = true
			}
			if res.MIMEType != "application/json" {
				t.Errorf("SEC-30 FAILED: Resource %s should have MIMEType application/json, got %s", res.URI, res.MIMEType)
			}
			if res.Name == "" || res.Description == "" {
				t.Errorf("SEC-30 FAILED: Resource %s is missing Name or Description", res.URI)
			}
		}

		for uri, found := range expectedURIs {
			if !found {
				t.Errorf("SEC-30 FAILED: Missing required MCP resource URI: %s", uri)
			}
		}
	})

	t.Run("Resources_HealthTelemetry", func(t *testing.T) {
		server := mcp.NewServer(nil, nil)
		readReq := `{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"airlock://health"}}`

		resp, err := server.HandleMessage(ctx, []byte(readReq))
		if err != nil {
			t.Fatalf("SEC-30 FAILED: resources/read airlock://health error: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("SEC-30 FAILED: airlock://health returned error: %+v", resp.Error)
		}

		readRes, ok := resp.Result.(*mcp.ReadResourceResult)
		if !ok || len(readRes.Contents) == 0 {
			t.Fatalf("SEC-30 FAILED: Invalid ReadResourceResult for health")
		}

		var healthData map[string]interface{}
		if err := json.Unmarshal([]byte(readRes.Contents[0].Text), &healthData); err != nil {
			t.Fatalf("SEC-30 FAILED: Failed to unmarshal health JSON payload: %v", err)
		}

		if healthData["status"] != "healthy" {
			t.Errorf("SEC-30 FAILED: Expected health status 'healthy', got %v", healthData["status"])
		}
		if healthData["platform"] == "" || healthData["architecture"] == "" {
			t.Errorf("SEC-30 FAILED: Missing platform or architecture in health telemetry")
		}
		if healthData["backend"] == "Unsupported" {
			t.Logf("Notice: Running on platform with backend: %v", healthData["backend"])
		}

		caps, ok := healthData["isolation_capabilities"].(map[string]interface{})
		if !ok {
			t.Fatalf("SEC-30 FAILED: Missing isolation_capabilities map in health telemetry")
		}
		if caps["network_egress_proxy"] != true {
			t.Errorf("SEC-30 FAILED: network_egress_proxy capability must be true")
		}
		if caps["environment_sanitization"] != true {
			t.Errorf("SEC-30 FAILED: environment_sanitization capability must be true")
		}
		if caps["argus_static_vetting"] != true {
			t.Errorf("SEC-30 FAILED: argus_static_vetting capability must be true")
		}
	})

	t.Run("Resources_PolicyActive_InvariantEnforcement", func(t *testing.T) {
		tempDir := t.TempDir()

		// Construct an adversarial airlock.yaml attempting to bypass invariants (V-01, V-03, V-06)
		adversarialYAML := `version: "1"
mode: "strict"
network:
  airgap: true
  allow_domains:
    - "malicious-exfil.com"
filesystem:
  allow_read:
    - "~/.ssh/id_rsa"
    - "~/.aws/credentials"
    - "/var/run/docker.sock"
  allow_write:
    - ".git/hooks/post-checkout"
env:
  allow:
    - "LD_PRELOAD"
    - "DYLD_INSERT_LIBRARIES"
`
		cfgPath := filepath.Join(tempDir, "airlock.yaml")
		if err := os.WriteFile(cfgPath, []byte(adversarialYAML), 0644); err != nil {
			t.Fatalf("SEC-30 FAILED: Failed to write adversarial config: %v", err)
		}

		resHandler := mcp.NewDefaultResourceHandler(mcp.WithResourceWorkspace(tempDir))
		server := mcp.NewServer(nil, nil, mcp.WithResourceHandler(resHandler))

		readReq := `{"jsonrpc":"2.0","id":4,"method":"resources/read","params":{"uri":"airlock://policy/active"}}`
		resp, err := server.HandleMessage(ctx, []byte(readReq))
		if err != nil {
			t.Fatalf("SEC-30 FAILED: resources/read airlock://policy/active error: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("SEC-30 FAILED: airlock://policy/active returned error: %+v", resp.Error)
		}

		readRes := resp.Result.(*mcp.ReadResourceResult)
		var policyData map[string]interface{}
		if err := json.Unmarshal([]byte(readRes.Contents[0].Text), &policyData); err != nil {
			t.Fatalf("SEC-30 FAILED: Failed to unmarshal policy resource JSON: %v", err)
		}

		if policyData["config_found"] != true {
			t.Errorf("SEC-30 FAILED: Expected config_found=true for created airlock.yaml")
		}

		// Verify guardrail warnings are surfaced
		warnings, ok := policyData["guardrail_warnings"].([]interface{})
		if !ok || len(warnings) == 0 {
			t.Errorf("SEC-30 FAILED: Expected guardrail warnings for adversarial permissions, got %d", len(warnings))
		}

		// Verify active_config has stripped the forbidden overrides
		activeCfg, ok := policyData["active_config"].(map[string]interface{})
		if !ok {
			t.Fatalf("SEC-30 FAILED: Missing active_config in policy resource")
		}

		fsCfg, ok := activeCfg["filesystem"].(map[string]interface{})
		if ok {
			allowRead, _ := fsCfg["allow_read"].([]interface{})
			for _, p := range allowRead {
				pStr := fmt.Sprintf("%v", p)
				if strings.Contains(pStr, ".ssh") || strings.Contains(pStr, ".aws") || strings.Contains(pStr, "docker.sock") {
					t.Errorf("SEC-30 INVARIANT VIOLATION: Sensitive path %s was NOT stripped from allow_read", pStr)
				}
			}
		}

		envCfg, ok := activeCfg["env"].(map[string]interface{})
		if ok {
			allowEnv, _ := envCfg["allow"].([]interface{})
			for _, e := range allowEnv {
				eStr := fmt.Sprintf("%v", e)
				if eStr == "LD_PRELOAD" || eStr == "DYLD_INSERT_LIBRARIES" {
					t.Errorf("SEC-30 INVARIANT VIOLATION: Dangerous dynamic linker variable %s was NOT stripped from env.allow", eStr)
				}
			}
		}

		// Verify immutable_invariants section is present
		invariants, ok := policyData["immutable_invariants"].(map[string]interface{})
		if !ok {
			t.Fatalf("SEC-30 FAILED: Missing immutable_invariants in policy resource")
		}
		if invariants["airgap_enforcement"] == nil || invariants["egress_proxy"] == nil {
			t.Errorf("SEC-30 FAILED: Invariants description missing airgap or proxy isolation details")
		}
	})

	t.Run("Resources_AuditLogTailing", func(t *testing.T) {
		tempDir := t.TempDir()
		auditLogFile := filepath.Join(tempDir, "audit.log")

		f, err := os.Create(auditLogFile)
		if err != nil {
			t.Fatalf("SEC-30 FAILED: Failed to create test audit log: %v", err)
		}
		logger := audit.NewFileLogger(f)

		// Emit execution, network egress, and security violation audit records
		_ = logger.LogExecution(audit.ExecutionRecord{
			Command:       "npm",
			Args:          []string{"install", "express"},
			WorkspaceRoot: tempDir,
			Airgap:        false,
			ExitCode:      0,
		})
		_ = logger.LogNetwork(audit.NetworkRecord{
			Protocol: "HTTPS",
			Host:     "registry.npmjs.org",
			Port:     443,
			Action:   "ALLOW",
			Reason:   "Allowed by baseline package registry allowlist",
		})
		_ = logger.LogSecurity(audit.SecurityRecord{
			Category: "EGRESS_DENIAL",
			Details:  "Connection to evil-exfil.com blocked by zero-trust egress filter",
		})
		_ = logger.Close()

		resHandler := mcp.NewDefaultResourceHandler(mcp.WithResourceAuditLog(auditLogFile))
		server := mcp.NewServer(nil, nil, mcp.WithResourceHandler(resHandler))

		readReq := `{"jsonrpc":"2.0","id":5,"method":"resources/read","params":{"uri":"airlock://audit/recent"}}`
		resp, err := server.HandleMessage(ctx, []byte(readReq))
		if err != nil {
			t.Fatalf("SEC-30 FAILED: resources/read airlock://audit/recent error: %v", err)
		}
		if resp.Error != nil {
			t.Fatalf("SEC-30 FAILED: airlock://audit/recent returned error: %+v", resp.Error)
		}

		readRes := resp.Result.(*mcp.ReadResourceResult)
		var records []map[string]interface{}
		if err := json.Unmarshal([]byte(readRes.Contents[0].Text), &records); err != nil {
			t.Fatalf("SEC-30 FAILED: Failed to unmarshal audit records: %v", err)
		}

		if len(records) != 3 {
			t.Fatalf("SEC-30 FAILED: Expected 3 audit records in tail, got %d", len(records))
		}

		typesFound := make(map[string]bool)
		for _, r := range records {
			if tStr, ok := r["type"].(string); ok {
				typesFound[tStr] = true
			}
		}

		if !typesFound[string(audit.EventExecution)] {
			t.Errorf("SEC-30 FAILED: Missing execution event in audit recent resource")
		}
		if !typesFound[string(audit.EventNetworkEgress)] {
			t.Errorf("SEC-30 FAILED: Missing network_egress event in audit recent resource")
		}
		if !typesFound[string(audit.EventSecurityViolation)] {
			t.Errorf("SEC-30 FAILED: Missing security_violation event in audit recent resource")
		}
	})

	t.Run("Prompts_ListAndGetTemplates", func(t *testing.T) {
		server := mcp.NewServer(nil, nil)

		// 1. prompts/list
		listReq := `{"jsonrpc":"2.0","id":6,"method":"prompts/list"}`
		resp, err := server.HandleMessage(ctx, []byte(listReq))
		if err != nil || resp.Error != nil {
			t.Fatalf("SEC-30 FAILED: prompts/list error: %v, rpc error: %+v", err, resp.Error)
		}

		listRes := resp.Result.(*mcp.ListPromptsResult)
		promptMap := make(map[string]mcp.Prompt)
		for _, p := range listRes.Prompts {
			promptMap[p.Name] = p
		}

		for _, name := range []string{mcp.PromptSecurityReview, mcp.PromptPreInstallAudit, mcp.PromptSandboxTroubleshoot} {
			if _, exists := promptMap[name]; !exists {
				t.Errorf("SEC-30 FAILED: Missing standard prompt %s", name)
			}
		}

		// 2. prompts/get security_review
		getSecReviewReq := `{
			"jsonrpc": "2.0",
			"id": 7,
			"method": "prompts/get",
			"params": {
				"name": "security_review",
				"arguments": {
					"target_path": "package.json",
					"context": "Adding new database driver"
				}
			}
		}`
		secResp, err := server.HandleMessage(ctx, []byte(getSecReviewReq))
		if err != nil || secResp.Error != nil {
			t.Fatalf("SEC-30 FAILED: prompts/get security_review error: %v, rpc error: %+v", err, secResp.Error)
		}
		secRes := secResp.Result.(*mcp.GetPromptResult)
		if len(secRes.Messages) == 0 {
			t.Fatalf("SEC-30 FAILED: Expected messages in security_review prompt")
		}
		secText := secRes.Messages[0].Content.Text
		if !strings.Contains(secText, "package.json") || !strings.Contains(secText, "airlock_vet") {
			t.Errorf("SEC-30 FAILED: security_review prompt missing required keywords or parameters")
		}

		// 3. prompts/get pre_install_audit
		getPreInstallReq := `{
			"jsonrpc": "2.0",
			"id": 8,
			"method": "prompts/get",
			"params": {
				"name": "pre_install_audit",
				"arguments": {
					"package_name": "cross-env",
					"ecosystem": "npm",
					"version": "7.0.3"
				}
			}
		}`
		preResp, err := server.HandleMessage(ctx, []byte(getPreInstallReq))
		if err != nil || preResp.Error != nil {
			t.Fatalf("SEC-30 FAILED: prompts/get pre_install_audit error: %v, rpc error: %+v", err, preResp.Error)
		}
		preRes := preResp.Result.(*mcp.GetPromptResult)
		preText := preRes.Messages[0].Content.Text
		if !strings.Contains(preText, "cross-env") || !strings.Contains(preText, "airlock_vet") {
			t.Errorf("SEC-30 FAILED: pre_install_audit prompt missing package name or vet instruction")
		}

		// 4. prompts/get sandbox_troubleshoot
		getTroubleshootReq := `{
			"jsonrpc": "2.0",
			"id": 9,
			"method": "prompts/get",
			"params": {
				"name": "sandbox_troubleshoot",
				"arguments": {
					"error_message": "Operation not permitted: write to ~/.ssh/config",
					"command": "npm install",
					"domain": "internal-corp.net"
				}
			}
		}`
		troubleResp, err := server.HandleMessage(ctx, []byte(getTroubleshootReq))
		if err != nil || troubleResp.Error != nil {
			t.Fatalf("SEC-30 FAILED: prompts/get sandbox_troubleshoot error: %v, rpc error: %+v", err, troubleResp.Error)
		}
		troubleRes := troubleResp.Result.(*mcp.GetPromptResult)
		troubleText := troubleRes.Messages[0].Content.Text
		if !strings.Contains(troubleText, "Operation not permitted") || !strings.Contains(troubleText, "airlock://audit/recent") {
			t.Errorf("SEC-30 FAILED: sandbox_troubleshoot prompt missing error context or audit resource link")
		}
	})

	t.Run("AdversarialErrorEnvelopes", func(t *testing.T) {
		server := mcp.NewServer(nil, nil)

		// 1. Malformed JSON
		badJSONResp, err := server.HandleMessage(ctx, []byte(`{invalid json`))
		if err != nil {
			t.Fatalf("SEC-30 FAILED: HandleMessage should not error on malformed JSON: %v", err)
		}
		if badJSONResp.Error == nil || badJSONResp.Error.Code != mcp.CodeParseError {
			t.Errorf("SEC-30 FAILED: Expected CodeParseError (-32700), got: %+v", badJSONResp.Error)
		}

		// 2. Unknown Method
		unknownMethodReq := `{"jsonrpc":"2.0","id":100,"method":"system/self_destruct"}`
		unknownResp, _ := server.HandleMessage(ctx, []byte(unknownMethodReq))
		if unknownResp.Error == nil || unknownResp.Error.Code != mcp.CodeMethodNotFound {
			t.Errorf("SEC-30 FAILED: Expected CodeMethodNotFound (-32601), got: %+v", unknownResp.Error)
		}

		// 3. resources/read missing uri
		missingURIReq := `{"jsonrpc":"2.0","id":101,"method":"resources/read","params":{}}`
		missingURIResp, _ := server.HandleMessage(ctx, []byte(missingURIReq))
		if missingURIResp.Error == nil || missingURIResp.Error.Code != mcp.CodeInvalidParams {
			t.Errorf("SEC-30 FAILED: Expected CodeInvalidParams for missing uri, got: %+v", missingURIResp.Error)
		}

		// 4. resources/read non-existent uri
		nonExistentURIReq := `{"jsonrpc":"2.0","id":102,"method":"resources/read","params":{"uri":"airlock://non/existent"}}`
		nonExistentResp, _ := server.HandleMessage(ctx, []byte(nonExistentURIReq))
		if nonExistentResp.Error == nil || nonExistentResp.Error.Code != mcp.CodeInvalidParams {
			t.Errorf("SEC-30 FAILED: Expected CodeInvalidParams for non-existent URI, got: %+v", nonExistentResp.Error)
		}

		// 5. prompts/get missing name
		missingNameReq := `{"jsonrpc":"2.0","id":103,"method":"prompts/get","params":{}}`
		missingNameResp, _ := server.HandleMessage(ctx, []byte(missingNameReq))
		if missingNameResp.Error == nil || missingNameResp.Error.Code != mcp.CodeInvalidParams {
			t.Errorf("SEC-30 FAILED: Expected CodeInvalidParams for missing prompt name, got: %+v", missingNameResp.Error)
		}

		// 6. prompts/get non-existent prompt
		nonExistentPromptReq := `{"jsonrpc":"2.0","id":104,"method":"prompts/get","params":{"name":"non_existent_prompt"}}`
		nonExistentPromptResp, _ := server.HandleMessage(ctx, []byte(nonExistentPromptReq))
		if nonExistentPromptResp.Error == nil || nonExistentPromptResp.Error.Code != mcp.CodeInvalidParams {
			t.Errorf("SEC-30 FAILED: Expected CodeInvalidParams for non-existent prompt, got: %+v", nonExistentPromptResp.Error)
		}
	})

	t.Run("StreamingPipedSession", func(t *testing.T) {
		input := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
			`{"jsonrpc":"2.0","id":2,"method":"resources/list"}` + "\n" +
			`{"jsonrpc":"2.0","id":3,"method":"resources/read","params":{"uri":"airlock://health"}}` + "\n" +
			`{"jsonrpc":"2.0","id":4,"method":"prompts/list"}` + "\n" +
			`{"jsonrpc":"2.0","id":5,"method":"prompts/get","params":{"name":"security_review","arguments":{"target_path":"main.go"}}}` + "\n" +
			`{"jsonrpc":"2.0","id":6,"method":"logging/setLevel","params":{"level":"debug"}}` + "\n" +
			`{"jsonrpc":"2.0","id":7,"method":"ping"}` + "\n"

		in := bytes.NewBufferString(input)
		out := &bytes.Buffer{}

		server := mcp.NewServer(in, out)
		if err := server.Serve(ctx); err != nil {
			t.Fatalf("SEC-30 FAILED: Serve streaming failed: %v", err)
		}

		lines := strings.Split(strings.TrimSpace(out.String()), "\n")
		if len(lines) != 7 {
			t.Fatalf("SEC-30 FAILED: Expected 7 response lines from stream, got %d:\n%s", len(lines), out.String())
		}

		for i, line := range lines {
			var resp mcp.Response
			if err := json.Unmarshal([]byte(line), &resp); err != nil {
				t.Errorf("SEC-30 FAILED: Line %d is invalid JSON response: %v", i+1, err)
			}
			if resp.Error != nil {
				t.Errorf("SEC-30 FAILED: Line %d returned unexpected error: %+v", i+1, resp.Error)
			}
		}
	})
}
