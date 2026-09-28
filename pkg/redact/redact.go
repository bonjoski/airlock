package redact

import (
	"bytes"
	"io"
	"regexp"
	"sync"
)

// SecretPattern defines a compiled regular expression and replacement template for redaction.
type SecretPattern struct {
	Name    string
	Pattern *regexp.Regexp
	Mask    string
}

var (
	defaultPatternsLock sync.RWMutex
	defaultPatterns     []SecretPattern
)

func init() {
	defaultPatterns = []SecretPattern{
		// 1. GitHub Tokens
		{
			Name:    "GITHUB_PAT",
			Pattern: regexp.MustCompile(`\b(ghp_[a-zA-Z0-9]{36}|github_pat_[a-zA-Z0-9_]{20,90})\b`),
			Mask:    "[REDACTED_SECRET:GITHUB_PAT]",
		},
		{
			Name:    "GITHUB_OAUTH_APP",
			Pattern: regexp.MustCompile(`\b(gho_[a-zA-Z0-9]{36}|ghu_[a-zA-Z0-9]{36}|ghs_[a-zA-Z0-9]{36}|ghr_[a-zA-Z0-9]{36})\b`),
			Mask:    "[REDACTED_SECRET:GITHUB_TOKEN]",
		},

		// 2. OpenAI API Keys
		{
			Name:    "OPENAI_KEY",
			Pattern: regexp.MustCompile(`\b(sk-[a-zA-Z0-9]{48,}|sk-proj-[a-zA-Z0-9_\-]{40,})\b`),
			Mask:    "[REDACTED_SECRET:OPENAI_KEY]",
		},

		// 3. Anthropic API Keys
		{
			Name:    "ANTHROPIC_KEY",
			Pattern: regexp.MustCompile(`\b(sk-ant-[a-zA-Z0-9_\-]{30,})\b`),
			Mask:    "[REDACTED_SECRET:ANTHROPIC_KEY]",
		},

		// 4. AWS Access Keys & Secret Keys
		{
			Name:    "AWS_ACCESS_KEY_ID",
			Pattern: regexp.MustCompile(`\b(AKIA[0-9A-Z]{16})\b`),
			Mask:    "[REDACTED_SECRET:AWS_KEY_ID]",
		},
		{
			Name:    "AWS_SECRET_ACCESS_KEY",
			Pattern: regexp.MustCompile(`(?i)(aws_secret_access_key|aws_secret_key)\s*[:=]\s*['"]?([a-zA-Z0-9/+=]{40})['"]?`),
			Mask:    "${1}=[REDACTED_SECRET:AWS_SECRET_KEY]",
		},

		// 5. Google Cloud API Keys
		{
			Name:    "GCP_API_KEY",
			Pattern: regexp.MustCompile(`\b(AIza[0-9A-Za-z\-_]{30,40})\b`),
			Mask:    "[REDACTED_SECRET:GCP_API_KEY]",
		},

		// 6. Slack API Tokens
		{
			Name:    "SLACK_TOKEN",
			Pattern: regexp.MustCompile(`\b(xox[baprs]-[0-9a-zA-Z]{10,48})\b`),
			Mask:    "[REDACTED_SECRET:SLACK_TOKEN]",
		},

		// 7. Generic PEM Private Key Blocks
		{
			Name:    "PRIVATE_KEY_PEM",
			Pattern: regexp.MustCompile(`-----BEGIN (?:[A-Z0-9_-]+ )?PRIVATE KEY-----[\s\S]*?-----END (?:[A-Z0-9_-]+ )?PRIVATE KEY-----`),
			Mask:    "[REDACTED_SECRET:PRIVATE_KEY_PEM]",
		},
		{
			Name:    "OPENSSH_PRIVATE_KEY",
			Pattern: regexp.MustCompile(`-----BEGIN OPENSSH PRIVATE KEY-----[\s\S]*?-----END OPENSSH PRIVATE KEY-----`),
			Mask:    "[REDACTED_SECRET:OPENSSH_PRIVATE_KEY]",
		},

		// 8. Generic High-Entropy Secret Assignments (e.g. secret=..., api_key=..., password=...)
		{
			Name:    "GENERIC_ASSIGNED_SECRET",
			Pattern: regexp.MustCompile(`(?i)\b(api[_-]?key|secret|token|password|auth|bearer)\s*([:=])\s*['"]([a-zA-Z0-9_\-\.\/+=]{20,})['"]`),
			Mask:    "${1}${2}\"[REDACTED_SECRET]\"",
		},
	}
}

// RedactString applies all default secret patterns to mask sensitive tokens from string content.
func RedactString(input string) string {
	if input == "" {
		return ""
	}

	defaultPatternsLock.RLock()
	defer defaultPatternsLock.RUnlock()

	result := input
	for _, p := range defaultPatterns {
		result = p.Pattern.ReplaceAllString(result, p.Mask)
	}
	return result
}

// RedactBytes applies all default secret patterns to mask sensitive tokens from byte slices.
func RedactBytes(input []byte) []byte {
	if len(input) == 0 {
		return input
	}
	return []byte(RedactString(string(input)))
}

// Writer wraps an underlying io.Writer and dynamically redacts secrets in-stream.
// It buffers line boundaries to ensure tokens split across chunked writes are detected and redacted.
type Writer struct {
	mu     sync.Mutex
	dest   io.Writer
	buf    []byte
	closed bool
}

// NewWriter returns a new in-stream redacting writer wrapping dest.
func NewWriter(dest io.Writer) *Writer {
	return &Writer{
		dest: dest,
		buf:  make([]byte, 0, 4096),
	}
}

// Write processes and writes data, redacting sensitive patterns before emitting to dest.
func (w *Writer) Write(p []byte) (n int, err error) {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return 0, io.ErrClosedPipe
	}

	w.buf = append(w.buf, p...)

	// Find the last newline to preserve partial tokens across chunk boundaries
	lastNL := bytes.LastIndexByte(w.buf, '\n')
	if lastNL == -1 {
		// If buffer exceeds max window size (e.g. 8KB without newlines), flush and redact
		if len(w.buf) > 8192 {
			redacted := RedactBytes(w.buf)
			_, err := w.dest.Write(redacted)
			w.buf = w.buf[:0]
			return len(p), err
		}
		// Hold until newline or flush
		return len(p), nil
	}

	toProcess := w.buf[:lastNL+1]
	redacted := RedactBytes(toProcess)
	_, writeErr := w.dest.Write(redacted)

	// Keep remaining tail in buffer
	remaining := w.buf[lastNL+1:]
	newBuf := make([]byte, len(remaining), 4096)
	copy(newBuf, remaining)
	w.buf = newBuf

	return len(p), writeErr
}

// Flush forces any remaining buffered bytes to be redacted and written.
func (w *Writer) Flush() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if len(w.buf) > 0 {
		redacted := RedactBytes(w.buf)
		_, err := w.dest.Write(redacted)
		w.buf = w.buf[:0]
		return err
	}
	return nil
}

// Close flushes the remaining buffered bytes and marks writer as closed.
func (w *Writer) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()

	if w.closed {
		return nil
	}
	w.closed = true

	if len(w.buf) > 0 {
		redacted := RedactBytes(w.buf)
		_, err := w.dest.Write(redacted)
		w.buf = w.buf[:0]
		return err
	}
	return nil
}
