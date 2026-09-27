package audit

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestFileLogger_AllEvents(t *testing.T) {
	var buf bytes.Buffer
	logger := NewFileLogger(&buf)

	// 1. Log Execution
	err := logger.LogExecution(ExecutionRecord{
		Command:       "npm",
		Args:          []string{"install", "express"},
		WorkspaceRoot: "/workspace/app",
		Airgap:        false,
		DurationMs:    150,
		ExitCode:      0,
	})
	if err != nil {
		t.Fatalf("LogExecution failed: %v", err)
	}

	// 2. Log Network
	err = logger.LogNetwork(NetworkRecord{
		Protocol:   "tcp",
		Host:       "registry.npmjs.org",
		Port:       443,
		Action:     "ALLOW",
		Reason:     "whitelisted_registry",
		ClientAddr: "127.0.0.1:54321",
	})
	if err != nil {
		t.Fatalf("LogNetwork failed: %v", err)
	}

	// 3. Log DNS
	err = logger.LogDNS(DNSRecord{
		Domain:      "registry.npmjs.org",
		QueryType:   "A",
		Action:      "ALLOW",
		Reason:      "whitelisted_domain",
		ResolvedIPs: []string{"104.16.1.1"},
	})
	if err != nil {
		t.Fatalf("LogDNS failed: %v", err)
	}

	// 4. Log Security
	err = logger.LogSecurity(SecurityRecord{
		Category: "file_access",
		Details:  "blocked attempt to read ~/.ssh/id_rsa",
	})
	if err != nil {
		t.Fatalf("LogSecurity failed: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(buf.String()), "\n")
	if len(lines) != 4 {
		t.Fatalf("Expected 4 log lines, got %d", len(lines))
	}

	var execRec ExecutionRecord
	if err := json.Unmarshal([]byte(lines[0]), &execRec); err != nil {
		t.Fatalf("Failed to parse execution JSON: %v", err)
	}
	if execRec.Type != EventExecution || execRec.Command != "npm" {
		t.Errorf("Unexpected execution record: %+v", execRec)
	}

	var netRec NetworkRecord
	if err := json.Unmarshal([]byte(lines[1]), &netRec); err != nil {
		t.Fatalf("Failed to parse network JSON: %v", err)
	}
	if netRec.Type != EventNetworkEgress || netRec.Host != "registry.npmjs.org" || netRec.Action != "ALLOW" {
		t.Errorf("Unexpected network record: %+v", netRec)
	}

	var dnsRec DNSRecord
	if err := json.Unmarshal([]byte(lines[2]), &dnsRec); err != nil {
		t.Fatalf("Failed to parse DNS JSON: %v", err)
	}
	if dnsRec.Type != EventDNSQuery || dnsRec.Domain != "registry.npmjs.org" {
		t.Errorf("Unexpected DNS record: %+v", dnsRec)
	}

	var secRec SecurityRecord
	if err := json.Unmarshal([]byte(lines[3]), &secRec); err != nil {
		t.Fatalf("Failed to parse security JSON: %v", err)
	}
	if secRec.Type != EventSecurityViolation || secRec.Category != "file_access" {
		t.Errorf("Unexpected security record: %+v", secRec)
	}
}

func TestFileLogger_FileWriteAndClose(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "test_audit.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("Failed to create log file: %v", err)
	}

	logger := NewFileLogger(f)
	if err := logger.LogExecution(ExecutionRecord{Command: "ls"}); err != nil {
		t.Fatalf("LogExecution failed: %v", err)
	}

	if err := logger.Close(); err != nil {
		t.Fatalf("Close failed: %v", err)
	}

	content, err := os.ReadFile(logPath)
	if err != nil {
		t.Fatalf("Failed to read log file: %v", err)
	}
	if !strings.Contains(string(content), `"command":"ls"`) {
		t.Errorf("Log file missing command record: %s", string(content))
	}
}

func TestNopLogger(t *testing.T) {
	nop := &NopLogger{}
	if err := nop.LogExecution(ExecutionRecord{}); err != nil {
		t.Errorf("NopLogger returned error: %v", err)
	}
	if err := nop.LogNetwork(NetworkRecord{}); err != nil {
		t.Errorf("NopLogger returned error: %v", err)
	}
	if err := nop.LogDNS(DNSRecord{}); err != nil {
		t.Errorf("NopLogger returned error: %v", err)
	}
	if err := nop.LogSecurity(SecurityRecord{}); err != nil {
		t.Errorf("NopLogger returned error: %v", err)
	}
	if err := nop.Close(); err != nil {
		t.Errorf("NopLogger returned error: %v", err)
	}
}
