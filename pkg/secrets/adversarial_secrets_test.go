package secrets

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/protocol"
)

// ADV-AIR-01: Zero-Residual Guarantee
// Verifies that after the client cleanup closure is called, the secret value slice
// is completely wiped in memory and cannot be recovered via residual pointers.
func TestAdversarial_ZeroResidualGuarantee(t *testing.T) {
	vault := map[string][]byte{
		"CRITICAL_SIGNING_KEY": []byte("prod-private-ec-key-384-bytes"),
	}
	sockPath, stop := startMockLocksmithDaemon(t, vault)
	defer stop()

	client := NewLocksmithClient(sockPath)

	resp, cleanup, err := client.RequestLease(context.Background(), "CRITICAL_SIGNING_KEY", 5*time.Minute, "")
	if err != nil {
		t.Fatalf("setup failed: %v", err)
	}

	// Capture a pointer or slice header to verify byte scrubbing
	capturedBytes := resp.SecretValue
	if string(capturedBytes) != "prod-private-ec-key-384-bytes" {
		t.Fatalf("unexpected value: %s", string(capturedBytes))
	}

	// Execute cleanup
	cleanup()

	// 1. Response field must be nil
	if resp.SecretValue != nil {
		t.Fatal("CRITICAL: resp.SecretValue was not nil'd after cleanup()")
	}

	// 2. Underlying slice backing array must be completely zeroed
	for i, b := range capturedBytes {
		if b != 0 {
			t.Fatalf("CRITICAL: Memory leak! Byte at index %d is %d (expected 0)", i, b)
		}
	}
	t.Log("PASS: Memory zeroed explicitly; zero residuals detected")
}

// ADV-AIR-02: Fail-Closed on Daemon Outage
// If the Locksmith daemon is killed or the socket is severed,
// Airlock MUST fail closed and refuse to proceed with unauthenticated/missing secrets.
func TestAdversarial_FailClosedOnDaemonOutage(t *testing.T) {
	nonExistentSocket := fmt.Sprintf("/tmp/dead-socket-%d.sock", time.Now().UnixNano())

	client := NewLocksmithClient(nonExistentSocket)

	_, _, err := client.RequestLease(context.Background(), "DATABASE_URL", time.Minute, "")
	if err == nil {
		t.Fatal("CRITICAL: Airlock failed open when daemon socket was unavailable!")
	}
	t.Logf("PASS: Airlock strictly failed closed: %v", err)
}

// ADV-AIR-03: Session Ticket Scope Boundary Verification
// Verifies that presenting a ticket for one domain blocks unauthorized secrets.
func TestAdversarial_SessionTicketBoundary(t *testing.T) {
	ticket := &protocol.SessionTicket{
		TicketID:       "sess-unit-scope",
		ExpiresAt:      time.Now().Add(10 * time.Minute),
		AllowedSecrets: []string{"OPENAI_API_KEY", "ANTHROPIC_API_KEY"},
	}

	if !ticket.PermitsSecret("OPENAI_API_KEY") {
		t.Fatal("expected OPENAI_API_KEY to be permitted")
	}
	if !ticket.PermitsSecret("openai_api_key") {
		t.Fatal("expected case-insensitive matching to permit openai_api_key")
	}
	if ticket.PermitsSecret("AWS_SECRET_ACCESS_KEY") {
		t.Fatal("CRITICAL: Session ticket permitted AWS_SECRET_ACCESS_KEY outside allowed scope!")
	}
	if ticket.PermitsSecret("OPENAI_API_KEY_ADMIN") {
		t.Fatal("CRITICAL: Session ticket allowed prefix extension attack!")
	}
	t.Log("PASS: Session ticket boundary strictly enforced against scope escapes")
}

// ADV-AIR-04: Opaque Lease Redemption Zeroization, Forbidden Env Rejection & DSSE Signing
func TestAdversarial_OpaqueLeaseRedeemAndSignDSSE(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("Unix domain sockets not supported on Windows")
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ed25519 key: %v", err)
	}

	sockPath := fmt.Sprintf("/tmp/airlock-opaque-adv-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%100000)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("listen unix socket: %v", err)
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
				var raw map[string]any
				if err := json.NewDecoder(c).Decode(&raw); err != nil {
					return
				}
				switch protocol.Action(fmt.Sprint(raw["action"])) {
				case protocol.ActionRedeemOpaqueLease:
					leaseID := fmt.Sprint(raw["lease_id"])
					sessionID := fmt.Sprint(raw["session_id"])
					if leaseID == "lease_forbidden_env" {
						_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
							Status:    protocol.StatusGranted,
							LeaseID:   leaseID,
							EnvVar:    "LD_PRELOAD",
							SecretB64: base64.StdEncoding.EncodeToString([]byte("/tmp/evil.so")),
						})
						return
					}
					if leaseID != "lease_valid01" || sessionID != "sess_alpha01" {
						_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
							Status: protocol.StatusDenied,
							Error:  "session mismatch or unknown lease",
						})
						return
					}
					_ = json.NewEncoder(c).Encode(protocol.RedeemOpaqueLeaseResponse{
						Status:    protocol.StatusGranted,
						LeaseID:   leaseID,
						EnvVar:    "STRIPE_API_KEY",
						SecretB64: base64.StdEncoding.EncodeToString([]byte("sk-live-CANARY999")),
						ExpiresAt: time.Now().Add(2 * time.Minute),
					})
				case protocol.ActionSignDSSE:
					paeB64 := fmt.Sprint(raw["pae_b64"])
					sessID := fmt.Sprint(raw["session_id"])
					pae, err := base64.StdEncoding.DecodeString(paeB64)
					if err != nil {
						_ = json.NewEncoder(c).Encode(protocol.SignDSSEResponse{
							Status: protocol.StatusDenied,
							Error:  "invalid pae_b64",
						})
						return
					}
					sig := ed25519.Sign(priv, pae)
					_ = json.NewEncoder(c).Encode(protocol.SignDSSEResponse{
						Status: protocol.StatusGranted,
						KeyID:  "spiffe://bonjoski.local/session/" + sessID,
						SigB64: base64.StdEncoding.EncodeToString(sig),
					})
				}
			}(conn)
		}
	}()

	client := NewLocksmithClient(sockPath)

	// 1. Valid redemption & explicit clear() zeroization
	envVar, secretBytes, cleanup, err := client.RedeemOpaqueLease(context.Background(), "lease_valid01", "sess_alpha01")
	if err != nil {
		t.Fatalf("RedeemOpaqueLease failed: %v", err)
	}
	if envVar != "STRIPE_API_KEY" || string(secretBytes) != "sk-live-CANARY999" {
		t.Fatalf("unexpected redeemed lease: env=%q val=%q", envVar, string(secretBytes))
	}
	cleanup()
	for i, b := range secretBytes {
		if b != 0 {
			t.Fatalf("secretBytes[%d] = %d after cleanup(), expected 0", i, b)
		}
	}

	// 2. Cross-session replay must fail closed
	if _, _, _, err := client.RedeemOpaqueLease(context.Background(), "lease_valid01", "sess_hijacker"); err == nil {
		t.Fatal("expected cross-session opaque lease redemption to fail closed")
	}

	// 3. Forbidden env var injection (LD_PRELOAD) must be rejected client-side
	if _, _, _, err := client.RedeemOpaqueLease(context.Background(), "lease_forbidden_env", "sess_alpha01"); err == nil {
		t.Fatal("expected forbidden env var LD_PRELOAD to be rejected")
	}

	// 4. SignDSSE round-trip verification
	pae := []byte("DSSEv1 28 application/vnd.in-toto+json 2 {}")
	keyID, sig, err := client.SignDSSE(context.Background(), "sess_alpha01", pae)
	if err != nil {
		t.Fatalf("SignDSSE failed: %v", err)
	}
	if keyID != "spiffe://bonjoski.local/session/sess_alpha01" {
		t.Fatalf("unexpected keyID: %q", keyID)
	}
	if !ed25519.Verify(pub, pae, sig) {
		t.Fatal("Ed25519 verification of SignDSSE signature failed")
	}
}
