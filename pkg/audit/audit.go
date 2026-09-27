// Package audit provides structured JSON telemetry and security audit logging
// for sandboxed executions, network egress, DNS queries, and security denials (Target 2).
package audit

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// EventType represents the category of the audit log entry.
type EventType string

const (
	EventExecution         EventType = "execution"
	EventNetworkEgress     EventType = "network_egress"
	EventDNSQuery          EventType = "dns_query"
	EventSecurityViolation EventType = "security_violation"
)

// BaseEntry contains metadata shared by all audit log records.
type BaseEntry struct {
	Timestamp string    `json:"timestamp"`
	Type      EventType `json:"type"`
}

// ExecutionRecord captures sandboxed command lifecycle events.
type ExecutionRecord struct {
	BaseEntry
	Command        string   `json:"command"`
	Args           []string `json:"args"`
	WorkspaceRoot  string   `json:"workspace_root"`
	Airgap         bool     `json:"airgap"`
	AllowDirectNet bool     `json:"allow_direct_net"`
	AllowedDomains []string `json:"allowed_domains,omitempty"`
	DurationMs     int64    `json:"duration_ms"`
	ExitCode       int      `json:"exit_code"`
	Error          string   `json:"error,omitempty"`
}

// NetworkRecord captures outbound HTTP/HTTPS proxy connection decisions.
type NetworkRecord struct {
	BaseEntry
	Protocol   string `json:"protocol"`
	Host       string `json:"host"`
	Port       int    `json:"port"`
	Action     string `json:"action"` // "ALLOW" or "DENY"
	Reason     string `json:"reason"`
	ClientAddr string `json:"client_addr,omitempty"`
}

// DNSRecord captures DNS resolution queries and policy decisions.
type DNSRecord struct {
	BaseEntry
	Domain      string   `json:"domain"`
	QueryType   string   `json:"query_type"`
	Action      string   `json:"action"` // "ALLOW" or "DENY"
	Reason      string   `json:"reason"`
	ResolvedIPs []string `json:"resolved_ips,omitempty"`
}

// SecurityRecord captures attempted sandbox escapes and policy violations.
type SecurityRecord struct {
	BaseEntry
	Category string `json:"category"`
	Details  string `json:"details"`
}

// Logger defines the interface for emitting structured telemetry.
type Logger interface {
	LogExecution(record ExecutionRecord) error
	LogNetwork(record NetworkRecord) error
	LogDNS(record DNSRecord) error
	LogSecurity(record SecurityRecord) error
	Close() error
}

// FileLogger writes JSON-lines audit records to an underlying destination.
type FileLogger struct {
	mu     sync.Mutex
	writer io.Writer
	closer io.Closer
}

// NewFileLogger creates an audit logger that writes to the given writer.
func NewFileLogger(w io.Writer) *FileLogger {
	var closer io.Closer
	if c, ok := w.(io.Closer); ok {
		closer = c
	}
	return &FileLogger{
		writer: w,
		closer: closer,
	}
}

// DefaultAuditLogPath returns the canonical path ~/.airlock/audit.log.
func DefaultAuditLogPath() (string, error) {
	home, err := os.UserHomeDir()
	if err != nil {
		return "", fmt.Errorf("audit: failed to determine user home directory: %w", err)
	}
	return filepath.Join(home, ".airlock", "audit.log"), nil
}

// NewDefaultLogger opens ~/.airlock/audit.log with 0600 permissions,
// creating parent directory ~/.airlock with 0700 permissions if needed.
func NewDefaultLogger() (*FileLogger, error) {
	logPath, err := DefaultAuditLogPath()
	if err != nil {
		return nil, err
	}

	dir := filepath.Dir(logPath)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return nil, fmt.Errorf("audit: failed to create audit directory %s: %w", dir, err)
	}

	f, err := os.OpenFile(logPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0600)
	if err != nil {
		return nil, fmt.Errorf("audit: failed to open audit log %s: %w", logPath, err)
	}

	return NewFileLogger(f), nil
}

func (l *FileLogger) writeRecord(record any) error {
	l.mu.Lock()
	defer l.mu.Unlock()

	data, err := json.Marshal(record)
	if err != nil {
		return fmt.Errorf("audit: failed to serialize audit entry: %w", err)
	}

	data = append(data, '\n')
	if _, err := l.writer.Write(data); err != nil {
		return fmt.Errorf("audit: failed to write audit entry: %w", err)
	}

	return nil
}

// LogExecution records a command execution event.
func (l *FileLogger) LogExecution(record ExecutionRecord) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	record.Type = EventExecution
	return l.writeRecord(record)
}

// LogNetwork records an outbound egress proxy attempt.
func (l *FileLogger) LogNetwork(record NetworkRecord) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	record.Type = EventNetworkEgress
	return l.writeRecord(record)
}

// LogDNS records a DNS query attempt.
func (l *FileLogger) LogDNS(record DNSRecord) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	record.Type = EventDNSQuery
	return l.writeRecord(record)
}

// LogSecurity records a security policy denial or sandbox escape attempt.
func (l *FileLogger) LogSecurity(record SecurityRecord) error {
	if record.Timestamp == "" {
		record.Timestamp = time.Now().UTC().Format(time.RFC3339)
	}
	record.Type = EventSecurityViolation
	return l.writeRecord(record)
}

// Close closes the underlying writer if it implements io.Closer.
func (l *FileLogger) Close() error {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.closer != nil {
		return l.closer.Close()
	}
	return nil
}

// NopLogger is a no-op implementation of Logger for testing or disabled telemetry.
type NopLogger struct{}

func (n *NopLogger) LogExecution(_ ExecutionRecord) error { return nil }
func (n *NopLogger) LogNetwork(_ NetworkRecord) error     { return nil }
func (n *NopLogger) LogDNS(_ DNSRecord) error             { return nil }
func (n *NopLogger) LogSecurity(_ SecurityRecord) error   { return nil }
func (n *NopLogger) Close() error                         { return nil }
