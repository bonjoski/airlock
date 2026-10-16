package audit

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// ArgusStreamLogger streams normalized audit events asynchronously to the Argus telemetry bus.
type ArgusStreamLogger struct {
	mu         sync.Mutex
	socketPath string
	ch         chan []byte
	stopCh     chan struct{}
	doneCh     chan struct{}
	closed     bool
}

// NewArgusStreamLogger initializes a non-blocking telemetry streamer to Argus.
func NewArgusStreamLogger(socketPath string) *ArgusStreamLogger {
	if socketPath == "" {
		socketPath = ResolveArgusSocket()
	}

	l := &ArgusStreamLogger{
		socketPath: socketPath,
		ch:         make(chan []byte, 1000), // Non-blocking async queue
		stopCh:     make(chan struct{}),
		doneCh:     make(chan struct{}),
	}

	go l.streamWorker()

	return l
}

// ResolveArgusSocket returns the active Argus daemon socket path.
func ResolveArgusSocket() string {
	if s := os.Getenv("ARGUS_SOCKET"); s != "" {
		return s
	}
	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		candidate := filepath.Join(home, ".argus", "argus.sock")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}
	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("argus-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}
	return filepath.Join(os.TempDir(), "argus.sock")
}

func (l *ArgusStreamLogger) streamWorker() {
	defer close(l.doneCh)

	var conn net.Conn
	defer func() {
		if conn != nil {
			_ = conn.Close()
		}
	}()

	dial := func() net.Conn {
		c, err := net.DialTimeout("unix", l.socketPath, 500*time.Millisecond)
		if err != nil {
			return nil
		}
		return c
	}

	for {
		select {
		case <-l.stopCh:
			return
		case data := <-l.ch:
			if conn == nil {
				conn = dial()
			}
			if conn != nil {
				_ = conn.SetWriteDeadline(time.Now().Add(500 * time.Millisecond))
				if _, err := conn.Write(append(data, '\n')); err != nil {
					_ = conn.Close()
					conn = nil
				}
			}
		}
	}
}

func (l *ArgusStreamLogger) enqueue(event any) {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return
	}
	l.mu.Unlock()

	data, err := json.Marshal(map[string]any{
		"action":    "telemetry_ingest",
		"telemetry": event,
	})
	if err != nil {
		return
	}

	select {
	case l.ch <- data:
	default:
		// Queue full: drop gracefully to avoid blocking execution path (VAL-04)
	}
}

func randTraceID() string {
	b := make([]byte, 16)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

func randSpanID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return hex.EncodeToString(b)
}

// LogExecution emits a command execution event.
func (l *ArgusStreamLogger) LogExecution(record ExecutionRecord) error {
	l.enqueue(map[string]any{
		"trace_id":   randTraceID(),
		"span_id":    randSpanID(),
		"timestamp":  time.Now(),
		"source":     "airlock",
		"event_type": "execution.completed",
		"severity":   "INFO",
		"target_pid": os.Getpid(),
		"details": map[string]any{
			"command":     record.Command,
			"args":        record.Args,
			"duration_ms": record.DurationMs,
			"exit_code":   record.ExitCode,
			"workspace":   record.WorkspaceRoot,
		},
	})
	return nil
}

// LogNetwork emits a network egress decision event.
func (l *ArgusStreamLogger) LogNetwork(record NetworkRecord) error {
	sev := "INFO"
	if record.Action == "DENY" {
		sev = "WARN"
	}
	l.enqueue(map[string]any{
		"trace_id":   randTraceID(),
		"span_id":    randSpanID(),
		"timestamp":  time.Now(),
		"source":     "airlock",
		"event_type": "network.egress",
		"severity":   sev,
		"details": map[string]any{
			"host":     record.Host,
			"port":     record.Port,
			"action":   record.Action,
			"reason":   record.Reason,
			"protocol": record.Protocol,
		},
	})
	return nil
}

// LogDNS emits a DNS resolution query event.
func (l *ArgusStreamLogger) LogDNS(record DNSRecord) error {
	sev := "INFO"
	if record.Action == "DENY" {
		sev = "WARN"
	}
	l.enqueue(map[string]any{
		"trace_id":   randTraceID(),
		"span_id":    randSpanID(),
		"timestamp":  time.Now(),
		"source":     "airlock",
		"event_type": "dns.query",
		"severity":   sev,
		"details": map[string]any{
			"domain": record.Domain,
			"type":   record.QueryType,
			"action": record.Action,
			"reason": record.Reason,
		},
	})
	return nil
}

// LogSecurity emits a security violation event (triggers Argus Killswitch if CRITICAL).
func (l *ArgusStreamLogger) LogSecurity(record SecurityRecord) error {
	l.enqueue(map[string]any{
		"trace_id":   randTraceID(),
		"span_id":    randSpanID(),
		"timestamp":  time.Now(),
		"source":     "airlock",
		"event_type": "security.violation",
		"severity":   "CRITICAL",
		"target_pid": os.Getpid(),
		"details": map[string]any{
			"category": record.Category,
			"details":  record.Details,
		},
	})
	return nil
}

// Close gracefully stops the worker and closes connection.
func (l *ArgusStreamLogger) Close() error {
	l.mu.Lock()
	if l.closed {
		l.mu.Unlock()
		return nil
	}
	l.closed = true
	l.mu.Unlock()

	close(l.stopCh)
	<-l.doneCh
	return nil
}

// MultiLogger fans out audit entries to multiple loggers.
type MultiLogger struct {
	loggers []Logger
}

// NewMultiLogger wraps multiple loggers into a single interface.
func NewMultiLogger(loggers ...Logger) *MultiLogger {
	return &MultiLogger{loggers: loggers}
}

func (m *MultiLogger) LogExecution(record ExecutionRecord) error {
	for _, l := range m.loggers {
		if l != nil {
			_ = l.LogExecution(record)
		}
	}
	return nil
}

func (m *MultiLogger) LogNetwork(record NetworkRecord) error {
	for _, l := range m.loggers {
		if l != nil {
			_ = l.LogNetwork(record)
		}
	}
	return nil
}

func (m *MultiLogger) LogDNS(record DNSRecord) error {
	for _, l := range m.loggers {
		if l != nil {
			_ = l.LogDNS(record)
		}
	}
	return nil
}

func (m *MultiLogger) LogSecurity(record SecurityRecord) error {
	for _, l := range m.loggers {
		if l != nil {
			_ = l.LogSecurity(record)
		}
	}
	return nil
}

func (m *MultiLogger) Close() error {
	for _, l := range m.loggers {
		if l != nil {
			_ = l.Close()
		}
	}
	return nil
}
