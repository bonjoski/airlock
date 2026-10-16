package secrets

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/protocol"
)

func startMockLocksmithDaemon(t *testing.T, secrets map[string][]byte) (string, func()) {
	sockPath := fmt.Sprintf("/tmp/airlock-ls-test-%d-%d.sock", os.Getpid(), time.Now().UnixNano()%10000)
	l, err := net.Listen("unix", sockPath)
	if err != nil {
		t.Fatalf("failed to listen on test socket: %v", err)
	}

	activeLeases := make(map[string]string)
	done := make(chan struct{})

	go func() {
		for {
			conn, err := l.Accept()
			if err != nil {
				select {
				case <-done:
					return
				default:
					return
				}
			}

			go func(c net.Conn) {
				defer c.Close()
				var baseReq struct {
					Action protocol.Action `json:"action"`
				}
				buf := make([]byte, 8192)
				n, err := c.Read(buf)
				if err != nil || n == 0 {
					return
				}

				if err := json.Unmarshal(buf[:n], &baseReq); err != nil {
					return
				}

				switch baseReq.Action {
				case protocol.ActionPing:
					_ = json.NewEncoder(c).Encode(map[string]string{"status": "PONG"})

				case protocol.ActionRequestLease:
					var req protocol.LeaseRequest
					_ = json.Unmarshal(buf[:n], &req)
					val, ok := secrets[req.SecretName]
					if !ok {
						_ = json.NewEncoder(c).Encode(&protocol.LeaseResponse{
							Status: protocol.StatusDenied,
							Error:  "secret not found in vault",
						})
						return
					}
					leaseID := fmt.Sprintf("lease-%d", time.Now().UnixNano())
					activeLeases[leaseID] = req.SecretName
					_ = json.NewEncoder(c).Encode(&protocol.LeaseResponse{
						Status:      protocol.StatusGranted,
						LeaseID:     leaseID,
						SecretValue: val,
						ExpiresAt:   time.Now().Add(5 * time.Minute),
					})

				case protocol.ActionRevokeLease:
					var req protocol.RevokeRequest
					_ = json.Unmarshal(buf[:n], &req)
					delete(activeLeases, req.LeaseID)
					_ = json.NewEncoder(c).Encode(&protocol.RevokeResponse{
						Success: true,
					})

				case protocol.ActionCreateSession:
					_ = json.NewEncoder(c).Encode(&protocol.SessionTicket{
						TicketID:       "sess-mock-ticket",
						ExpiresAt:      time.Now().Add(15 * time.Minute),
						AllowedSecrets: []string{"*"},
					})
				}
			}(conn)
		}
	}()

	cleanup := func() {
		close(done)
		_ = l.Close()
		_ = os.Remove(sockPath)
	}

	return sockPath, cleanup
}

func TestLocksmithClient_Ping(t *testing.T) {
	sockPath, stop := startMockLocksmithDaemon(t, nil)
	defer stop()

	client := NewLocksmithClient(sockPath)
	if err := client.Ping(context.Background()); err != nil {
		t.Fatalf("Ping failed: %v", err)
	}
}

func TestLocksmithClient_RequestLeaseAndRevoke(t *testing.T) {
	vault := map[string][]byte{
		"OPENAI_API_KEY": []byte("sk-proj-testkey987654321"),
	}
	sockPath, stop := startMockLocksmithDaemon(t, vault)
	defer stop()

	client := NewLocksmithClient(sockPath)

	resp, revoke, err := client.RequestLease(context.Background(), "OPENAI_API_KEY", 5*time.Minute, "")
	if err != nil {
		t.Fatalf("RequestLease error: %v", err)
	}
	if resp.Status != protocol.StatusGranted {
		t.Fatalf("expected GRANTED, got %s", resp.Status)
	}
	if string(resp.SecretValue) != "sk-proj-testkey987654321" {
		t.Fatalf("unexpected secret value: %s", string(resp.SecretValue))
	}

	// Verify revoke function zeroes memory
	revoke()
	if resp.SecretValue != nil {
		t.Fatalf("expected secret bytes to be zeroed/nil after revoke, got %v", resp.SecretValue)
	}
}

func TestLocksmithClient_DeniedSecret(t *testing.T) {
	sockPath, stop := startMockLocksmithDaemon(t, map[string][]byte{})
	defer stop()

	client := NewLocksmithClient(sockPath)
	_, _, err := client.RequestLease(context.Background(), "NONEXISTENT_KEY", 5*time.Minute, "")
	if err == nil {
		t.Fatal("expected error for nonexistent secret, got nil")
	}
}

func TestLocksmithClient_CreateSession(t *testing.T) {
	sockPath, stop := startMockLocksmithDaemon(t, nil)
	defer stop()

	client := NewLocksmithClient(sockPath)
	ticket, err := client.CreateSession(context.Background(), 15*time.Minute, []string{"*"})
	if err != nil {
		t.Fatalf("CreateSession error: %v", err)
	}
	if ticket.TicketID != "sess-mock-ticket" {
		t.Fatalf("unexpected ticket ID: %s", ticket.TicketID)
	}
}
