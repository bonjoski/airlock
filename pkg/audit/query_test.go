package audit

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func createSampleLogFile(t *testing.T) (string, []Entry) {
	t.Helper()
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "audit.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create test log: %v", err)
	}
	defer f.Close()

	logger := NewFileLogger(f)

	// 1. Execution record
	_ = logger.LogExecution(ExecutionRecord{
		Command:       "npm",
		Args:          []string{"install", "express"},
		WorkspaceRoot: "/workspace/app",
		Airgap:        false,
		DurationMs:    120,
		ExitCode:      0,
	})

	// 2. Execution record (failed)
	_ = logger.LogExecution(ExecutionRecord{
		Command:       "cargo",
		Args:          []string{"build"},
		WorkspaceRoot: "/workspace/rust-app",
		DurationMs:    350,
		ExitCode:      1,
		Error:         "build failure",
	})

	// 3. Network egress ALLOW
	_ = logger.LogNetwork(NetworkRecord{
		Protocol:   "tcp",
		Host:       "registry.npmjs.org",
		Port:       443,
		Action:     "ALLOW",
		Reason:     "whitelisted_registry",
		ClientAddr: "127.0.0.1:50000",
	})

	// 4. Network egress DENY
	_ = logger.LogNetwork(NetworkRecord{
		Protocol:   "tcp",
		Host:       "evil-exfil.attacker.com",
		Port:       443,
		Action:     "DENY",
		Reason:     "domain_not_whitelisted",
		ClientAddr: "127.0.0.1:50001",
	})

	// 5. DNS Query ALLOW
	_ = logger.LogDNS(DNSRecord{
		Domain:      "registry.npmjs.org",
		QueryType:   "A",
		Action:      "ALLOW",
		Reason:      "whitelisted_domain",
		ResolvedIPs: []string{"104.16.1.1"},
	})

	// 6. DNS Query DENY (DNS Tunneling attempt)
	_ = logger.LogDNS(DNSRecord{
		Domain:    "secretdata.tunnel.attacker.com",
		QueryType: "TXT",
		Action:    "DENY",
		Reason:    "domain_not_whitelisted",
	})

	// 7. Security Violation
	_ = logger.LogSecurity(SecurityRecord{
		Category: "file_access",
		Details:  "blocked attempt to access ~/.ssh/id_rsa",
	})

	// 8. Second npm execution
	_ = logger.LogExecution(ExecutionRecord{
		Command:       "npm",
		Args:          []string{"test"},
		WorkspaceRoot: "/workspace/app",
		DurationMs:    50,
		ExitCode:      0,
	})

	engine := NewQueryEngine(logPath)
	entries, err := engine.ReadAll()
	if err != nil {
		t.Fatalf("failed to read test entries: %v", err)
	}

	return logPath, entries
}

func TestQuery_ReadAllAndNonExistent(t *testing.T) {
	tempDir := t.TempDir()
	nonExistentPath := filepath.Join(tempDir, "does_not_exist.log")
	engine := NewQueryEngine(nonExistentPath)

	entries, err := engine.ReadAll()
	if err != nil {
		t.Fatalf("expected nil error for non-existent file, got: %v", err)
	}
	if len(entries) != 0 {
		t.Fatalf("expected 0 entries for non-existent file, got %d", len(entries))
	}
}

func TestQuery_Filters(t *testing.T) {
	logPath, _ := createSampleLogFile(t)
	engine := NewQueryEngine(logPath)

	// Filter by RecordType: exec
	execEntries, err := engine.Query(Filter{RecordType: "exec"})
	if err != nil {
		t.Fatalf("Query exec failed: %v", err)
	}
	if len(execEntries) != 3 {
		t.Errorf("Expected 3 exec entries, got %d", len(execEntries))
	}

	// Filter by RecordType: net / network
	netEntries, err := engine.Query(Filter{RecordType: "net"})
	if err != nil {
		t.Fatalf("Query net failed: %v", err)
	}
	if len(netEntries) != 2 {
		t.Errorf("Expected 2 net entries, got %d", len(netEntries))
	}

	// Filter by RecordType: dns
	dnsEntries, err := engine.Query(Filter{RecordType: "dns"})
	if err != nil {
		t.Fatalf("Query dns failed: %v", err)
	}
	if len(dnsEntries) != 2 {
		t.Errorf("Expected 2 dns entries, got %d", len(dnsEntries))
	}

	// Filter by RecordType: security
	secEntries, err := engine.Query(Filter{RecordType: "security"})
	if err != nil {
		t.Fatalf("Query security failed: %v", err)
	}
	if len(secEntries) != 1 {
		t.Errorf("Expected 1 security entry, got %d", len(secEntries))
	}

	// Filter by Status: allow
	allowEntries, err := engine.Query(Filter{Status: "allow"})
	if err != nil {
		t.Fatalf("Query allow failed: %v", err)
	}
	// 2 execs + 1 net allow + 1 dns allow = 4
	if len(allowEntries) != 4 {
		t.Errorf("Expected 4 allow entries, got %d", len(allowEntries))
	}

	// Filter by Status: deny
	denyEntries, err := engine.Query(Filter{Status: "deny"})
	if err != nil {
		t.Fatalf("Query deny failed: %v", err)
	}
	// 1 failed exec + 1 net deny + 1 dns deny + 1 sec violation = 4
	if len(denyEntries) != 4 {
		t.Errorf("Expected 4 deny/blocked entries, got %d", len(denyEntries))
	}

	// Filter with Search: "attacker.com"
	attackerEntries, err := engine.Query(Filter{Search: "attacker.com"})
	if err != nil {
		t.Fatalf("Query search attacker.com failed: %v", err)
	}
	if len(attackerEntries) != 2 {
		t.Errorf("Expected 2 entries with attacker.com, got %d", len(attackerEntries))
	}

	// Filter with Limit
	limitedEntries, err := engine.Query(Filter{Limit: 2})
	if err != nil {
		t.Fatalf("Query limit failed: %v", err)
	}
	if len(limitedEntries) != 2 {
		t.Errorf("Expected 2 entries with limit=2, got %d", len(limitedEntries))
	}
}

func TestQuery_TimeFilters(t *testing.T) {
	logPath, entries := createSampleLogFile(t)
	engine := NewQueryEngine(logPath)

	if len(entries) == 0 {
		t.Fatalf("No sample entries found")
	}

	// Filter with Since after all entries
	futureTime := time.Now().Add(1 * time.Hour)
	futureEntries, err := engine.Query(Filter{Since: futureTime})
	if err != nil {
		t.Fatalf("Query since future failed: %v", err)
	}
	if len(futureEntries) != 0 {
		t.Errorf("Expected 0 future entries, got %d", len(futureEntries))
	}

	// Filter with Since before all entries
	pastTime := time.Now().Add(-1 * time.Hour)
	pastEntries, err := engine.Query(Filter{Since: pastTime})
	if err != nil {
		t.Fatalf("Query since past failed: %v", err)
	}
	if len(pastEntries) != len(entries) {
		t.Errorf("Expected %d past entries, got %d", len(entries), len(pastEntries))
	}
}

func TestQuery_ComputeStats(t *testing.T) {
	logPath, _ := createSampleLogFile(t)
	engine := NewQueryEngine(logPath)

	stats, err := engine.Stats(Filter{})
	if err != nil {
		t.Fatalf("Stats calculation failed: %v", err)
	}

	if stats.TotalRecords != 8 {
		t.Errorf("Expected 8 total records, got %d", stats.TotalRecords)
	}
	if stats.TotalExecutions != 3 {
		t.Errorf("Expected 3 total executions, got %d", stats.TotalExecutions)
	}
	if stats.AllowedEgressAttempts != 1 {
		t.Errorf("Expected 1 allowed egress attempt, got %d", stats.AllowedEgressAttempts)
	}
	if stats.DeniedEgressAttempts != 1 {
		t.Errorf("Expected 1 denied egress attempt, got %d", stats.DeniedEgressAttempts)
	}
	if stats.AllowedDNSQueries != 1 {
		t.Errorf("Expected 1 allowed DNS query, got %d", stats.AllowedDNSQueries)
	}
	if stats.BlockedDNSTunneling != 1 {
		t.Errorf("Expected 1 blocked DNS tunneling query, got %d", stats.BlockedDNSTunneling)
	}
	if stats.SecurityEvents != 1 {
		t.Errorf("Expected 1 security event, got %d", stats.SecurityEvents)
	}

	// Check Top Domains
	if len(stats.TopDomains) == 0 {
		t.Fatalf("Expected top domains to be populated")
	}
	// registry.npmjs.org was in 1 net ALLOW and 1 DNS ALLOW = count 2
	if stats.TopDomains[0].Domain != "registry.npmjs.org" || stats.TopDomains[0].Count != 2 {
		t.Errorf("Expected top domain registry.npmjs.org with count 2, got: %+v", stats.TopDomains[0])
	}

	// Check Top Commands
	if len(stats.TopCommands) == 0 {
		t.Fatalf("Expected top commands to be populated")
	}
	// npm was executed 2 times
	if stats.TopCommands[0].Command != "npm" || stats.TopCommands[0].Count != 2 {
		t.Errorf("Expected top command npm with count 2, got: %+v", stats.TopCommands[0])
	}
}

func TestQuery_ExportJSONAndCSV(t *testing.T) {
	_, entries := createSampleLogFile(t)

	// Test JSON export
	var jsonBuf bytes.Buffer
	if err := ExportEntries(entries, ExportJSON, &jsonBuf); err != nil {
		t.Fatalf("ExportEntries JSON failed: %v", err)
	}

	var parsedJSON []Entry
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsedJSON); err != nil {
		t.Fatalf("Failed to parse exported JSON: %v", err)
	}
	if len(parsedJSON) != len(entries) {
		t.Errorf("Expected %d JSON entries, got %d", len(entries), len(parsedJSON))
	}

	// Test CSV export
	var csvBuf bytes.Buffer
	if err := ExportEntries(entries, ExportCSV, &csvBuf); err != nil {
		t.Fatalf("ExportEntries CSV failed: %v", err)
	}

	reader := csv.NewReader(&csvBuf)
	records, err := reader.ReadAll()
	if err != nil {
		t.Fatalf("Failed to read exported CSV: %v", err)
	}
	// 1 header row + 8 data rows = 9
	if len(records) != len(entries)+1 {
		t.Errorf("Expected %d CSV rows (including header), got %d", len(entries)+1, len(records))
	}
	if records[0][0] != "timestamp" || records[0][1] != "type" || records[0][2] != "status" {
		t.Errorf("Unexpected CSV header: %v", records[0])
	}
}

func TestQuery_LiveTailing(t *testing.T) {
	tempDir := t.TempDir()
	logPath := filepath.Join(tempDir, "tail_test.log")

	f, err := os.Create(logPath)
	if err != nil {
		t.Fatalf("failed to create log: %v", err)
	}

	logger := NewFileLogger(f)
	_ = logger.LogExecution(ExecutionRecord{Command: "echo", Args: []string{"initial"}})

	engine := NewQueryEngine(logPath)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	var outBuf bytes.Buffer
	var mu sync.Mutex

	type safeBuffer struct {
		buf *bytes.Buffer
		mu  *sync.Mutex
	}

	sb := &safeBuffer{buf: &outBuf, mu: &mu}

	// Run Tail in background with follow=true
	tailDone := make(chan error, 1)
	go func() {
		// Custom writer wrapper for concurrent safe write
		w := &threadSafeWriter{buf: sb.buf, mu: sb.mu}
		tailDone <- engine.Tail(ctx, 5, true, w)
	}()

	// Write new entries while tailing is active
	time.Sleep(50 * time.Millisecond)
	_ = logger.LogNetwork(NetworkRecord{Host: "new-site.com", Port: 80, Action: "ALLOW"})
	_ = logger.LogSecurity(SecurityRecord{Category: "sandbox_escape", Details: "blocked ptrace call"})

	// Poll until both streamed records appear in output or timeout
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		cur := outBuf.String()
		mu.Unlock()
		if strings.Contains(cur, "new-site.com") && strings.Contains(cur, "sandbox_escape") {
			cancel()
			break
		}
		time.Sleep(20 * time.Millisecond)
	}

	err = <-tailDone
	_ = logger.Close()
	_ = f.Close()

	if err != nil && err != context.DeadlineExceeded && err != context.Canceled {
		t.Fatalf("Tail returned unexpected error: %v", err)
	}

	mu.Lock()
	output := outBuf.String()
	mu.Unlock()

	if !strings.Contains(output, "initial") {
		t.Errorf("Tail output missing initial record: %s", output)
	}
	if !strings.Contains(output, "new-site.com") {
		t.Errorf("Tail output missing streamed network record: %s", output)
	}
	if !strings.Contains(output, "sandbox_escape") {
		t.Errorf("Tail output missing streamed security record: %s", output)
	}
}

type threadSafeWriter struct {
	buf *bytes.Buffer
	mu  *sync.Mutex
}

func (w *threadSafeWriter) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	return w.buf.Write(p)
}
