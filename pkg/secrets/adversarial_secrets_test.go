package secrets

import (
	"context"
	"fmt"
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
