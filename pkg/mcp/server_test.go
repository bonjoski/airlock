package mcp

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestMCPServer_Initialize(t *testing.T) {
	s := NewServer(nil, nil, WithVersion("1.1.0"))
	reqJSON := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2024-11-05"}}`

	resp, err := s.HandleMessage(context.Background(), []byte(reqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected RPC error: %+v", resp.Error)
	}

	result, ok := resp.Result.(InitializeResult)
	if !ok {
		t.Fatalf("Expected InitializeResult, got %T", resp.Result)
	}
	if result.ServerInfo.Name != "airlock-mcp" {
		t.Errorf("Expected server name 'airlock-mcp', got %s", result.ServerInfo.Name)
	}
	if result.ServerInfo.Version != "1.1.0" {
		t.Errorf("Expected version '1.1.0', got %s", result.ServerInfo.Version)
	}
}

func TestMCPServer_Ping(t *testing.T) {
	s := NewServer(nil, nil)
	reqJSON := `{"jsonrpc":"2.0","id":2,"method":"ping"}`

	resp, err := s.HandleMessage(context.Background(), []byte(reqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected RPC error: %+v", resp.Error)
	}
}

func TestMCPServer_ToolsList(t *testing.T) {
	s := NewServer(nil, nil)
	reqJSON := `{"jsonrpc":"2.0","id":3,"method":"tools/list"}`

	resp, err := s.HandleMessage(context.Background(), []byte(reqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected RPC error: %+v", resp.Error)
	}

	result, ok := resp.Result.(ListToolsResult)
	if !ok {
		t.Fatalf("Expected ListToolsResult, got %T", resp.Result)
	}

	toolNames := make(map[string]bool)
	for _, tool := range result.Tools {
		toolNames[tool.Name] = true
	}

	if !toolNames["airlock_exec"] {
		t.Errorf("Missing expected tool 'airlock_exec'")
	}
	if !toolNames["airlock_vet"] {
		t.Errorf("Missing expected tool 'airlock_vet'")
	}
	if !toolNames["airlock_policy_check"] {
		t.Errorf("Missing expected tool 'airlock_policy_check'")
	}
}

func TestMCPServer_ToolCall_Exec(t *testing.T) {
	tempDir := t.TempDir()
	s := NewServer(nil, nil)

	reqJSON := fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"id": 4,
		"method": "tools/call",
		"params": {
			"name": "airlock_exec",
			"arguments": {
				"command": "echo hello-mcp-airlock",
				"workspace": "%s",
				"airgap": true
			}
		}
	}`, tempDir)

	resp, err := s.HandleMessage(context.Background(), []byte(reqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected RPC error: %+v", resp.Error)
	}

	toolRes, ok := resp.Result.(*CallToolResult)
	if !ok {
		t.Fatalf("Expected *CallToolResult, got %T", resp.Result)
	}
	if len(toolRes.Content) == 0 {
		t.Fatalf("Expected content in tool response")
	}

	var execRes ExecResult
	if err := json.Unmarshal([]byte(toolRes.Content[0].Text), &execRes); err != nil {
		t.Fatalf("Failed to parse ExecResult text: %v\nPayload: %s", err, toolRes.Content[0].Text)
	}

	if execRes.ExitCode != 0 {
		t.Errorf("Expected exit code 0, got %d, error: %s", execRes.ExitCode, execRes.Error)
	}
	if !strings.Contains(execRes.Stdout, "hello-mcp-airlock") {
		t.Errorf("Expected stdout to contain 'hello-mcp-airlock', got: %q", execRes.Stdout)
	}
}

func TestMCPServer_ToolCall_Vet(t *testing.T) {
	s := NewServer(nil, nil)

	// Benign command
	reqJSON := `{
		"jsonrpc": "2.0",
		"id": 5,
		"method": "tools/call",
		"params": {
			"name": "airlock_vet",
			"arguments": {
				"command": "npm install lodash",
				"strict": true
			}
		}
	}`

	resp, err := s.HandleMessage(context.Background(), []byte(reqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected RPC error: %+v", resp.Error)
	}

	toolRes, ok := resp.Result.(*CallToolResult)
	if !ok {
		t.Fatalf("Expected *CallToolResult, got %T", resp.Result)
	}
	if toolRes.IsError {
		t.Errorf("Expected benign vet check to succeed, got isError=true")
	}

	// Malicious typosquatting command
	badReqJSON := `{
		"jsonrpc": "2.0",
		"id": 6,
		"method": "tools/call",
		"params": {
			"name": "airlock_vet",
			"arguments": {
				"command": "npm install crossenv",
				"strict": true
			}
		}
	}`

	badResp, err := s.HandleMessage(context.Background(), []byte(badReqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	badToolRes := badResp.Result.(*CallToolResult)
	if !badToolRes.IsError {
		t.Errorf("Expected malicious typosquat check to fail with isError=true")
	}

	var badVetRes VetResult
	if err := json.Unmarshal([]byte(badToolRes.Content[0].Text), &badVetRes); err != nil {
		t.Fatalf("Failed to parse VetResult: %v", err)
	}
	if badVetRes.HighCritical == 0 {
		t.Errorf("Expected High/Critical findings for crossenv, got %d", badVetRes.HighCritical)
	}
}

func TestMCPServer_ToolCall_PolicyCheck(t *testing.T) {
	tempDir := t.TempDir()
	cfgPath := filepath.Join(tempDir, "airlock.yaml")
	cfgContent := `version: "1"
mode: "strict"
network:
  airgap: false
  allow_domains:
    - "api.mycorp.internal"
`
	if err := os.WriteFile(cfgPath, []byte(cfgContent), 0644); err != nil {
		t.Fatalf("Failed to write config: %v", err)
	}

	s := NewServer(nil, nil)

	reqJSON := fmt.Sprintf(`{
		"jsonrpc": "2.0",
		"id": 7,
		"method": "tools/call",
		"params": {
			"name": "airlock_policy_check",
			"arguments": {
				"config_path": "%s",
				"domain": "api.mycorp.internal",
				"path": "~/.ssh/id_rsa",
				"env_var": "LD_PRELOAD"
			}
		}
	}`, cfgPath)

	resp, err := s.HandleMessage(context.Background(), []byte(reqJSON))
	if err != nil {
		t.Fatalf("HandleMessage error: %v", err)
	}
	if resp.Error != nil {
		t.Fatalf("Unexpected RPC error: %+v", resp.Error)
	}

	toolRes := resp.Result.(*CallToolResult)
	var policyRes PolicyCheckResult
	if err := json.Unmarshal([]byte(toolRes.Content[0].Text), &policyRes); err != nil {
		t.Fatalf("Failed to parse PolicyCheckResult: %v", err)
	}

	// 1. Verify domain allowed
	if policyRes.DomainCheck["allowed"] != true {
		t.Errorf("Expected api.mycorp.internal to be allowed")
	}

	// 2. Verify SSH path denied
	if policyRes.PathCheck["guardrail_restricted"] != true {
		t.Errorf("Expected ~/.ssh path to be guardrail_restricted")
	}

	// 3. Verify LD_PRELOAD denied
	if policyRes.EnvCheck["guardrail_restricted"] != true {
		t.Errorf("Expected LD_PRELOAD to be guardrail_restricted")
	}
}

func TestMCPServer_StreamPipe(t *testing.T) {
	inputData := `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}` + "\n" +
		`{"jsonrpc":"2.0","id":2,"method":"ping"}` + "\n"

	in := bytes.NewBufferString(inputData)
	out := &bytes.Buffer{}

	server := NewServer(in, out)
	if err := server.Serve(context.Background()); err != nil {
		t.Fatalf("Serve failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(out.String()), "\n")
	if len(lines) != 2 {
		t.Fatalf("Expected 2 response lines, got %d:\n%s", len(lines), out.String())
	}
}
