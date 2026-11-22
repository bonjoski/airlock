package secrets_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/mcp"
	"github.com/bonjoski/airlock/pkg/protocol"
)

// TestOpaqueLease_InjectAndScrubStdout verifies FR-LEASE-03 / ADV-LEASE-01:
// 1. Redeems an opaque lease handle over a mock Locksmith UDS server.
// 2. Injects the secret into the sandboxed child process environment.
// 3. If the child prints the canary secret (sk-live-CANARY999) to stdout or stderr,
//    Airlock scrubs it completely and fails closed with UB-MCP-v1 FixForwardError
//    (code: "AIRLOCK_SECRET_LEAK_BLOCKED", exit_code: 40) with ZERO canary bytes returned.
// 4. Cross-session lease hijack is denied fail-closed (exit_code: 40).
func TestOpaqueLease_InjectAndScrubStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix domain sockets not supported on Windows in this test")
	}

	const canarySecret = "sk-live-CANARY999"
	const leaseID = "lease_01JDX9N8ZCANARY"
	const validSession = "sess_01JDX9J00VALID"

	sockPath := fmt.Sprintf("/tmp/airlock-opaque-mcp-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%100000)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on mock locksmith socket: %v", err)
	}
	defer func() {
		_ = l.Close()
		_ = os.Remove(sockPath)
	}()

	var mu sync.Mutex
	redeemRequests := 0

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				var req protocol.RedeemOpaqueLeaseRequest
				if err := json.NewDecoder(c).Decode(&req); err != nil {
					return
				}
				if req.Action != protocol.ActionRedeemOpaqueLease {
					_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
						Status: protocol.StatusDenied,
						Error:  "unsupported action",
					})
					return
				}

				mu.Lock()
				redeemRequests++
				mu.Unlock()

				if req.Version != protocol.ProtocolVersion || req.ClientPID <= 0 || req.ProcessStartTime <= 0 {
					_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
						Status: protocol.StatusDenied,
						Error:  "invalid client attestation metadata",
					})
					return
				}
				if req.LeaseID != leaseID || req.SessionID != validSession {
					_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
						Status: protocol.StatusDenied,
						Error:  "cross-session or unknown lease rejected",
					})
					return
				}

				_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
					Status:    protocol.StatusGranted,
					LeaseID:   leaseID,
					EnvVar:    "STRIPE_API_KEY",
					SecretB64: base64.StdEncoding.EncodeToString([]byte(canarySecret)),
					ExpiresAt: time.Now().Add(2 * time.Minute),
				})
			}(conn)
		}
	}()

	t.Setenv("LOCKSMITH_SOCKET", sockPath)
	t.Setenv("FABRIAL_RECEIPT_DIR", "")

	wsDir := t.TempDir()
	handler := mcp.NewDefaultToolHandler()

	// 1. Child prints the leased canary secret -> MUST fail closed with exit_code == 40 and ZERO canary bytes
	t.Run("StdoutLeakFailsClosedAndScrubsCanary", func(t *testing.T) {
		rawArgs, _ := json.Marshal(map[string]any{
			"command":       "/bin/sh",
			"args":          []string{"-c", "printf 'leaked=%s\\n' \"$STRIPE_API_KEY\""},
			"workspace":     wsDir,
			"airgap":        true,
			"secret_leases": []string{leaseID},
			"session_id":    validSession,
			"emit_receipt":  false,
		})

		res, err := handler.HandleExec(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleExec returned unexpected error: %v", err)
		}
		if !res.IsError {
			t.Fatalf("expected IsError=true when child leaks canary secret; got result=%+v", res)
		}

		// Serialize entire CallToolResult to verify ZERO raw canary bytes anywhere
		fullJSON, err := json.Marshal(res)
		if err != nil {
			t.Fatalf("marshal CallToolResult: %v", err)
		}
		if strings.Contains(string(fullJSON), canarySecret) {
			t.Fatalf("CRITICAL SECRET LEAK: canary %q appeared in MCP CallToolResult: %s", canarySecret, string(fullJSON))
		}

		// Skip gracefully only if host Linux kernel has bwrap/userns unavailable
		if res.StructuredContent != nil {
			scBytes, _ := json.Marshal(res.StructuredContent)
			var sc map[string]any
			_ = json.Unmarshal(scBytes, &sc)
			if dw, ok := sc["deep_why"].(string); ok && (strings.Contains(dw, "unprivileged user namespaces are disabled") || strings.Contains(dw, "bwrap")) {
				t.Skip("bwrap/userns unavailable on host")
			}

			if sc["code"] != "AIRLOCK_SECRET_LEAK_BLOCKED" {
				t.Errorf("expected structuredContent.code == AIRLOCK_SECRET_LEAK_BLOCKED, got %v (payload: %s)", sc["code"], string(scBytes))
			}
			if sc["exit_code"] != float64(mcp.ExitSecretGuardBlock) {
				t.Errorf("expected structuredContent.exit_code == 40, got %v", sc["exit_code"])
			}
		} else {
			t.Fatalf("expected non-nil structuredContent on secret leak block")
		}

		// Verify calm <= 3 lines in Content[0].Text
		if len(res.Content) == 0 {
			t.Fatalf("expected calm human content")
		}
		lines := strings.Split(strings.TrimSpace(res.Content[0].Text), "\n")
		if len(lines) > 3 {
			t.Errorf("expected <= 3 calm lines in content[0].text, got %d:\n%s", len(lines), res.Content[0].Text)
		}
	})

	// 2. Child uses the leased secret internally without printing it -> succeeds with zero leak
	t.Run("NonLeakingUsageSucceeds", func(t *testing.T) {
		rawArgs, _ := json.Marshal(map[string]any{
			"command":       "/bin/sh",
			"args":          []string{"-c", "test \"$STRIPE_API_KEY\" = \"sk-live-CANARY999\" && echo 'verified-len-ok'"},
			"workspace":     wsDir,
			"airgap":        true,
			"secret_leases": []string{leaseID},
			"session_id":    validSession,
			"emit_receipt":  false,
		})

		res, err := handler.HandleExec(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}
		fullJSON, _ := json.Marshal(res)
		if strings.Contains(string(fullJSON), canarySecret) {
			t.Fatalf("CRITICAL SECRET LEAK: canary appeared in non-leaking response: %s", string(fullJSON))
		}
		if res.IsError {
			if strings.Contains(string(fullJSON), "unprivileged user namespaces are disabled") || strings.Contains(string(fullJSON), "bwrap") {
				t.Skip("bwrap/userns unavailable on host")
			}
			t.Fatalf("expected non-leaking leased execution to succeed, got error: %s", string(fullJSON))
		}
		if !strings.Contains(res.Content[0].Text, "verified-len-ok") {
			t.Errorf("expected stdout to confirm injected env var matched inside child, got: %s", res.Content[0].Text)
		}
	})

	// 3. Cross-session hijack attempt fails closed with exit_code == 40
	t.Run("CrossSessionHijackBlocked", func(t *testing.T) {
		rawArgs, _ := json.Marshal(map[string]any{
			"command":       "/bin/echo",
			"args":          []string{"should-never-run"},
			"workspace":     wsDir,
			"airgap":        true,
			"secret_leases": []string{leaseID},
			"session_id":    "sess_ATTACKER999",
			"emit_receipt":  false,
		})

		res, err := handler.HandleExec(context.Background(), rawArgs)
		if err != nil {
			t.Fatalf("HandleExec error: %v", err)
		}
		if !res.IsError {
			t.Fatalf("expected cross-session lease hijack to fail closed")
		}
		scBytes, _ := json.Marshal(res.StructuredContent)
		var sc map[string]any
		_ = json.Unmarshal(scBytes, &sc)
		if sc["exit_code"] != float64(mcp.ExitSecretGuardBlock) {
			t.Errorf("expected exit_code 40 on lease denial, got %v", sc["exit_code"])
		}
		if sc["code"] != "AIRLOCK_LEASE_DENIED" {
			t.Errorf("expected code AIRLOCK_LEASE_DENIED, got %v", sc["code"])
		}
	})

	mu.Lock()
	count := redeemRequests
	mu.Unlock()
	if count < 3 {
		t.Errorf("expected at least 3 mock UDS redeem_opaque_lease requests, got %d", count)
	}
}
