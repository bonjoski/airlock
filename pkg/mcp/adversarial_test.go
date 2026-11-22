package mcp

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/protocol"
)

var (
	ubCodeRe      = regexp.MustCompile(`^[A-Z][A-Z0-9_]{2,63}$`)
	ubReceiptIDRe = regexp.MustCompile(`^rcpt_[0-9A-Za-z]+$`)
	ubToolRe      = regexp.MustCompile(`^[a-z][a-z0-9_]{2,63}$`)
	blprKeyIDRe   = regexp.MustCompile(`^spiffe://bonjoski\.local/session/sess_[0-9A-Za-z]+$`)
	blprSessionRe = regexp.MustCompile(`^sess_[0-9A-Za-z]+$`)
	blprSHA256Re  = regexp.MustCompile(`^[a-f0-9]{64}$`)
	blprGitSHARe  = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
)

func assertUBMCPv1Conformance(t *testing.T, res *CallToolResult, expectedExitCode int) map[string]any {
	t.Helper()
	if res == nil {
		t.Fatal("expected non-nil CallToolResult")
	}
	if !res.IsError {
		t.Fatalf("expected IsError=true, got false")
	}
	if len(res.Content) == 0 {
		t.Fatalf("expected non-empty Content")
	}

	// Calm <= 3 lines and zero ANSI escape/control bytes in human text
	text := res.Content[0].Text
	if strings.ContainsAny(text, "\x1b\x07\u009b\u009d\ufffd") {
		t.Errorf("content[0].text contains forbidden ANSI/control bytes: %q", text)
	}
	lines := strings.Split(strings.TrimSpace(text), "\n")
	if len(lines) > 3 {
		t.Errorf("expected calm <=3-line human text, got %d lines:\n%s", len(lines), text)
	}

	if res.StructuredContent == nil {
		t.Fatalf("expected non-nil structuredContent")
	}
	raw, err := json.Marshal(res.StructuredContent)
	if err != nil {
		t.Fatalf("marshal structuredContent: %v", err)
	}
	if strings.ContainsAny(string(raw), "\x1b\x07\u009b\u009d\ufffd") {
		t.Errorf("structuredContent contains forbidden ANSI/control bytes: %s", string(raw))
	}

	var obj map[string]any
	if err := json.Unmarshal(raw, &obj); err != nil {
		t.Fatalf("unmarshal structuredContent: %v", err)
	}

	// Verify additionalProperties: false against ub-mcp-v1-error.schema.json
	allowedKeys := map[string]bool{
		"schema_version":  true,
		"tool":            true,
		"code":            true,
		"exit_code":       true,
		"retryable":       true,
		"summary":         true,
		"remediation_cmd": true,
		"why":             true,
		"deep_why":        true,
		"self_heal":       true,
		"receipt_id":      true,
		"references":      true,
	}
	for k := range obj {
		if !allowedKeys[k] {
			t.Errorf("ub-mcp-v1 schema violation: unexpected property %q", k)
		}
	}

	requiredKeys := []string{"schema_version", "tool", "code", "exit_code", "retryable", "summary", "remediation_cmd", "why"}
	for _, k := range requiredKeys {
		if _, ok := obj[k]; !ok {
			t.Errorf("ub-mcp-v1 schema violation: missing required property %q", k)
		}
	}

	if obj["schema_version"] != UBMCPv1SchemaVersion {
		t.Errorf("expected schema_version %q, got %v", UBMCPv1SchemaVersion, obj["schema_version"])
	}
	if obj["tool"] != "airlock" {
		t.Errorf("expected tool 'airlock', got %v", obj["tool"])
	}
	if code, ok := obj["code"].(string); !ok || !ubCodeRe.MatchString(code) {
		t.Errorf("invalid code %v", obj["code"])
	}
	if ec, ok := obj["exit_code"].(float64); !ok || int(ec) != expectedExitCode {
		t.Errorf("expected exit_code %d, got %v (full: %s)", expectedExitCode, obj["exit_code"], string(raw))
	}
	if _, ok := obj["retryable"].(bool); !ok {
		t.Errorf("expected boolean retryable, got %T", obj["retryable"])
	}
	if s, ok := obj["summary"].(string); !ok || len(s) == 0 || len([]rune(s)) > 240 {
		t.Errorf("invalid summary length/type: %v", obj["summary"])
	}
	if r, ok := obj["remediation_cmd"].(string); !ok || len(r) == 0 || len([]rune(r)) > 256 {
		t.Errorf("invalid remediation_cmd length/type: %v", obj["remediation_cmd"])
	}
	if w, ok := obj["why"].(string); !ok || len(w) == 0 || len([]rune(w)) > 280 {
		t.Errorf("invalid why length/type: %v", obj["why"])
	}
	if rid, exists := obj["receipt_id"]; exists {
		if s, ok := rid.(string); !ok || !ubReceiptIDRe.MatchString(s) {
			t.Errorf("invalid receipt_id %v", rid)
		}
	}
	if sh, exists := obj["self_heal"]; exists {
		shMap, ok := sh.(map[string]any)
		if !ok {
			t.Errorf("self_heal must be object, got %T", sh)
		} else {
			if st, ok := shMap["suggested_tool"].(string); !ok || !ubToolRe.MatchString(st) {
				t.Errorf("invalid self_heal.suggested_tool %v", shMap["suggested_tool"])
			}
			if _, ok := shMap["suggested_args"].(map[string]any); !ok {
				t.Errorf("self_heal.suggested_args must be object")
			}
			if _, ok := shMap["requires_human_approval"].(bool); !ok {
				t.Errorf("self_heal.requires_human_approval must be boolean")
			}
		}
	}
	return obj
}

// TestMCP_UBMCPv1SchemaConformance verifies structuredContent fields, ANSI stripping,
// calm <=3-line human text, and deterministic exit codes 20, 30, and 40.
func TestMCP_UBMCPv1SchemaConformance(t *testing.T) {
	t.Setenv("FABRIAL_RECEIPT_DIR", "")
	handler := NewDefaultToolHandler()

	// 1. Exit code 20: airlock_vet supply-chain block
	t.Run("ExitCode20_SupplyChainVetBlock", func(t *testing.T) {
		rawArgs, _ := json.Marshal(map[string]any{
			"command": "npm install crossenv",
			"strict":  true,
		})
		res, err := handler.HandleVet(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleVet error: %v", err)
		}
		obj := assertUBMCPv1Conformance(t, res, ExitSupplyChainBlock)
		if obj["code"] != "AIRLOCK_VET_BLOCKED" {
			t.Errorf("expected AIRLOCK_VET_BLOCKED, got %v", obj["code"])
		}
	})

	// 2. Exit code 30: sandbox confinement denial (reading ~/.ssh/id_rsa)
	t.Run("ExitCode30_SandboxViolation", func(t *testing.T) {
		if runtime.GOOS == "windows" {
			t.Skip("filesystem Seatbelt/bwrap confinement test is Unix-only")
		}
		homeDir, err := os.UserHomeDir()
		if err != nil {
			t.Fatalf("UserHomeDir: %v", err)
		}
		sshDir := filepath.Join(homeDir, ".ssh")
		_ = os.MkdirAll(sshDir, 0700)
		sshKey := filepath.Join(sshDir, "airlock_ubmcp_probe")
		if err := os.WriteFile(sshKey, []byte("probe-key"), 0600); err != nil {
			t.Fatalf("write probe ssh key: %v", err)
		}
		defer os.Remove(sshKey)

		rawArgs, _ := json.Marshal(map[string]any{
			"command":      "/bin/cat",
			"args":         []string{sshKey},
			"workspace":    t.TempDir(),
			"airgap":       true,
			"emit_receipt": false,
		})
		res, err := handler.HandleExec(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}
		obj := assertUBMCPv1Conformance(t, res, ExitSandboxViolation)
		if obj["code"] != "AIRLOCK_SANDBOX_DENIED" {
			t.Errorf("expected AIRLOCK_SANDBOX_DENIED, got %v", obj["code"])
		}
	})

	// 3. Exit code 40: opaque secret lease denial (unreachable daemon)
	t.Run("ExitCode40_OpaqueLeaseDenied", func(t *testing.T) {
		t.Setenv("LOCKSMITH_SOCKET", filepath.Join(t.TempDir(), "nonexistent.sock"))
		rawArgs, _ := json.Marshal(map[string]any{
			"command":       "/bin/echo",
			"args":          []string{"hi"},
			"workspace":     t.TempDir(),
			"airgap":        true,
			"secret_leases": []string{"lease_unreachable01"},
			"session_id":    "sess_test40",
			"emit_receipt":  false,
		})
		res, err := handler.HandleExec(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}
		obj := assertUBMCPv1Conformance(t, res, ExitSecretGuardBlock)
		if obj["code"] != "AIRLOCK_LEASE_DENIED" {
			t.Errorf("expected AIRLOCK_LEASE_DENIED, got %v", obj["code"])
		}
	})

	// 4. ANSI / OSC 52 / CSI / Bidi stripping invariant
	t.Run("ANSIAndControlCharStripping", func(t *testing.T) {
		hostile := &UBMCPError{
			Code:           "AIRLOCK_SANDBOX_DENIED",
			ExitCode:       ExitSandboxViolation,
			Retryable:      true,
			Summary:        "Blocked \x1b[31mred\x1b[0m and \x1b]52;c;Y21k\x07 clipboard\u202eattack\nline2",
			RemediationCmd: "airlock explain sandbox\x1b[2J --why",
			Why:            "Confinement\u009b31m protects \x00host secrets.",
			DeepWhy:        "Trace \x1b]0;pwned\x1b\\ details",
			References:     []string{"https://github.com/bonjoski/airlock", "not-a-uri"},
		}
		res := NewUBMCPErrorResult(hostile)
		obj := assertUBMCPv1Conformance(t, res, ExitSandboxViolation)
		if strings.Contains(obj["summary"].(string), "\x1b") || strings.Contains(obj["summary"].(string), "\u202e") || strings.Contains(obj["summary"].(string), "\n") {
			t.Errorf("summary was not cleanly sanitized: %q", obj["summary"])
		}
		refs, ok := obj["references"].([]any)
		if !ok || len(refs) != 1 || refs[0] != "https://github.com/bonjoski/airlock" {
			t.Errorf("expected non-URI references to be dropped, got: %v", obj["references"])
		}
	})
}

// TestMCP_BLPRReceiptRejectsSymlinkDir verifies that a symlinked FABRIAL_RECEIPT_DIR
// (or symlinked parent) fails closed with exit_code 10 and writes zero bytes to the target.
// It also validates signed BLPR-v1 DSSE receipt emission via mock Locksmith sign_dsse.
func TestMCP_BLPRReceiptRejectsSymlinkDir(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("symlink/O_NOFOLLOW test requires Unix")
	}

	handler := NewDefaultToolHandler()

	// 1. Direct symlinked FABRIAL_RECEIPT_DIR fails closed
	t.Run("DirectSymlinkFailsClosed", func(t *testing.T) {
		targetDir := t.TempDir()
		linkParent := t.TempDir()
		symlinkDir := filepath.Join(linkParent, "receipts-link")
		if err := os.Symlink(targetDir, symlinkDir); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		t.Setenv("FABRIAL_RECEIPT_DIR", symlinkDir)
		t.Setenv("FABRIAL_SESSION_ID", "sess_symlink01")

		rawArgs, _ := json.Marshal(map[string]any{
			"command":      "/bin/echo",
			"args":         []string{"hello"},
			"workspace":    t.TempDir(),
			"airgap":       true,
			"emit_receipt": true,
		})

		res, err := handler.HandleExec(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}
		obj := assertUBMCPv1Conformance(t, res, ExitPolicyDeny)
		if obj["code"] != "AIRLOCK_RECEIPT_POLICY_DENIED" {
			t.Errorf("expected AIRLOCK_RECEIPT_POLICY_DENIED, got %v", obj["code"])
		}

		// Verify zero files written into symlink target
		entries, err := os.ReadDir(targetDir)
		if err != nil {
			t.Fatalf("ReadDir targetDir: %v", err)
		}
		if len(entries) != 0 {
			t.Fatalf("CRITICAL: symlink target directory was modified (%d entries)", len(entries))
		}
	})

	// 2. Symlinked parent of FABRIAL_RECEIPT_DIR fails closed
	t.Run("SymlinkParentFailsClosed", func(t *testing.T) {
		targetDir := t.TempDir()
		linkParent := t.TempDir()
		symlinkParent := filepath.Join(linkParent, "parent-link")
		if err := os.Symlink(targetDir, symlinkParent); err != nil {
			t.Fatalf("create parent symlink: %v", err)
		}

		t.Setenv("FABRIAL_RECEIPT_DIR", filepath.Join(symlinkParent, "sess_child01"))
		t.Setenv("FABRIAL_SESSION_ID", "sess_child01")

		rawArgs, _ := json.Marshal(map[string]any{
			"command":      "npm install lodash",
			"strict":       true,
			"emit_receipt": true,
		})
		res, err := handler.HandleVet(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleVet error: %v", err)
		}
		obj := assertUBMCPv1Conformance(t, res, ExitPolicyDeny)
		if obj["code"] != "AIRLOCK_RECEIPT_POLICY_DENIED" {
			t.Errorf("expected AIRLOCK_RECEIPT_POLICY_DENIED, got %v", obj["code"])
		}

		entries, _ := os.ReadDir(targetDir)
		if len(entries) != 0 {
			t.Fatalf("CRITICAL: symlink parent target was modified (%d entries)", len(entries))
		}
	})

	// 3. Valid non-symlink receipt dir + mock Locksmith sign_dsse produces schema-valid, Ed25519-verified BLPR-v1 receipt (0600)
	t.Run("SignedBLPRv1ReceiptValidAndMode0600", func(t *testing.T) {
		pub, priv, err := ed25519.GenerateKey(rand.Reader)
		if err != nil {
			t.Fatalf("GenerateKey: %v", err)
		}

		sockPath := fmt.Sprintf("/tmp/airlock-dsse-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%100000)
		l, err := net.Listen("unix", sockPath)
		if err != nil {
			t.Fatalf("listen unix: %v", err)
		}
		defer func() {
			_ = l.Close()
			_ = os.Remove(sockPath)
		}()

		go func() {
			for {
				conn, err := l.Accept()
				if err != nil {
					return
				}
				go func(c net.Conn) {
					defer c.Close()
					var req protocol.SignDSSERequest
					if err := json.NewDecoder(c).Decode(&req); err != nil {
						return
					}
					if req.Action != protocol.ActionSignDSSE {
						return
					}
					pae, err := base64.StdEncoding.DecodeString(req.PAEB64)
					if err != nil {
						return
					}
					sig := ed25519.Sign(priv, pae)
					_ = json.NewEncoder(c).Encode(protocol.SignDSSEResponse{
						Status: protocol.StatusGranted,
						KeyID:  "spiffe://bonjoski.local/session/" + req.SessionID,
						SigB64: base64.StdEncoding.EncodeToString(sig),
					})
				}(conn)
			}
		}()

		receiptDir := filepath.Join(t.TempDir(), "receipts")
		t.Setenv("FABRIAL_RECEIPT_DIR", receiptDir)
		t.Setenv("FABRIAL_SESSION_ID", "sess_01JDX9SIGN")
		t.Setenv("LOCKSMITH_SOCKET", sockPath)

		rawArgs, _ := json.Marshal(map[string]any{
			"command":   "npm install lodash",
			"strict":    true,
			"workspace": t.TempDir(),
		})
		res, err := handler.HandleVet(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleVet error: %v", err)
		}
		if res.IsError {
			t.Fatalf("expected benign airlock_vet to succeed, got error: %+v", res)
		}

		entries, err := os.ReadDir(receiptDir)
		if err != nil {
			t.Fatalf("ReadDir receiptDir: %v", err)
		}
		if len(entries) != 1 {
			t.Fatalf("expected 1 receipt file, got %d", len(entries))
		}
		fullPath := filepath.Join(receiptDir, entries[0].Name())
		fi, err := os.Stat(fullPath)
		if err != nil {
			t.Fatalf("Stat receipt file: %v", err)
		}
		if fi.Mode().Perm() != 0600 {
			t.Errorf("expected receipt file mode 0600, got %04o", fi.Mode().Perm())
		}

		rawReceipt, err := os.ReadFile(fullPath)
		if err != nil {
			t.Fatalf("ReadFile receipt: %v", err)
		}
		var env DSSEEnvelope
		if err := json.Unmarshal(rawReceipt, &env); err != nil {
			t.Fatalf("unmarshal DSSEEnvelope: %v", err)
		}
		if env.PayloadType != DSSEPayloadType {
			t.Fatalf("unexpected payloadType: %q", env.PayloadType)
		}
		if len(env.Signatures) != 1 {
			t.Fatalf("expected 1 signature, got %d", len(env.Signatures))
		}
		if !blprKeyIDRe.MatchString(env.Signatures[0].KeyID) {
			t.Errorf("keyid %q does not match BLPR-v1 schema pattern", env.Signatures[0].KeyID)
		}

		payloadBytes, err := base64.StdEncoding.DecodeString(env.Payload)
		if err != nil {
			t.Fatalf("decode payload: %v", err)
		}
		sigBytes, err := base64.StdEncoding.DecodeString(env.Signatures[0].Sig)
		if err != nil {
			t.Fatalf("decode sig: %v", err)
		}
		if !ed25519.Verify(pub, PAE(env.PayloadType, payloadBytes), sigBytes) {
			t.Fatal("DSSE Ed25519 signature verification failed")
		}

		var stmt Statement
		if err := json.Unmarshal(payloadBytes, &stmt); err != nil {
			t.Fatalf("unmarshal Statement: %v", err)
		}
		if stmt.Type != StatementTypeV1 || stmt.PredicateType != PredicateTypeV1 {
			t.Errorf("unexpected statement/predicate types: %q / %q", stmt.Type, stmt.PredicateType)
		}
		if len(stmt.Subject) == 0 || !blprSHA256Re.MatchString(stmt.Subject[0].Digest["sha256"]) {
			t.Errorf("invalid subject digest: %+v", stmt.Subject)
		}
		if stmt.Predicate.SchemaVersion != BLPRSchemaVersion || !ubReceiptIDRe.MatchString(stmt.Predicate.ReceiptID) {
			t.Errorf("invalid predicate header: %+v", stmt.Predicate)
		}
		if !blprSessionRe.MatchString(stmt.Predicate.Session.SessionID) || !blprGitSHARe.MatchString(stmt.Predicate.Session.WorktreeHeadSHA) {
			t.Errorf("invalid session lineage: %+v", stmt.Predicate.Session)
		}
		if stmt.Predicate.Producer.Tool != "airlock" || stmt.Predicate.Producer.Stage != "scaffolding_deps" || !stmt.Predicate.Proven {
			t.Errorf("invalid producer/proven: %+v", stmt.Predicate)
		}
	})

	// 4. Unsigned local test mode works gracefully when no Locksmith daemon is listening
	t.Run("UnsignedLocalGracefulWhenNoDaemon", func(t *testing.T) {
		receiptDir := filepath.Join(t.TempDir(), "receipts-unsigned")
		t.Setenv("FABRIAL_RECEIPT_DIR", receiptDir)
		t.Setenv("FABRIAL_SESSION_ID", "sess_01JDX9UNSIGNED")
		t.Setenv("LOCKSMITH_SOCKET", filepath.Join(t.TempDir(), "missing.sock"))

		rawArgs, _ := json.Marshal(map[string]any{
			"command":   "npm install lodash",
			"strict":    true,
			"workspace": t.TempDir(),
		})
		res, err := handler.HandleVet(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleVet error: %v", err)
		}
		if res.IsError {
			t.Fatalf("expected unsigned local mode to succeed gracefully, got error: %+v", res)
		}

		entries, err := os.ReadDir(receiptDir)
		if err != nil || len(entries) != 1 {
			t.Fatalf("expected 1 unsigned receipt file, got %d (err=%v)", len(entries), err)
		}
		rawReceipt, _ := os.ReadFile(filepath.Join(receiptDir, entries[0].Name()))
		var env DSSEEnvelope
		_ = json.Unmarshal(rawReceipt, &env)
		payloadBytes, _ := base64.StdEncoding.DecodeString(env.Payload)
		var stmt Statement
		_ = json.Unmarshal(payloadBytes, &stmt)
		if stmt.Predicate.Proven {
			t.Errorf("expected Proven=false in unsigned local mode")
		}
		if len(env.Signatures) != 0 {
			t.Errorf("expected 0 signatures in unsigned local mode, got %d", len(env.Signatures))
		}
	})
}
