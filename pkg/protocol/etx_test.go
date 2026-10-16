package protocol_test

import (
	"os"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/protocol"
)

func TestAirlockClientIdentity(t *testing.T) {
	ident, err := protocol.GetCurrentClientIdentity()
	if err != nil {
		t.Fatalf("failed to get current client identity: %v", err)
	}
	if ident.PID != os.Getpid() {
		t.Errorf("expected PID %d, got %d", os.Getpid(), ident.PID)
	}
	if ident.StartTime <= 0 {
		t.Errorf("expected positive start time, got %d", ident.StartTime)
	}
}

func TestAirlockLeaseRequestValidation(t *testing.T) {
	req := protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        os.Getpid(),
		ProcessStartTime: 12345,
		SecretName:       "ANTHROPIC_API_KEY",
		LeaseTTL:         time.Minute,
	}

	if err := req.Validate(); err != nil {
		t.Fatalf("expected valid request, got: %v", err)
	}
}
