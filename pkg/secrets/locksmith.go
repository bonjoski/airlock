package secrets

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"time"

	"github.com/bonjoski/airlock/pkg/protocol"
)

// LocksmithClient provides the client interface for requesting and managing
// ephemeral credentials from the Locksmith resident daemon.
type LocksmithClient struct {
	socketPath string
}

// NewLocksmithClient initializes a client targeting the specified or discovered socket.
func NewLocksmithClient(socketPath string) *LocksmithClient {
	if socketPath == "" {
		socketPath = ResolveLocksmithSocket()
	}
	return &LocksmithClient{socketPath: socketPath}
}

// ResolveLocksmithSocket finds the active Locksmith daemon socket path.
func ResolveLocksmithSocket() string {
	if sock := os.Getenv("LOCKSMITH_SOCKET"); sock != "" {
		return sock
	}

	home, err := os.UserHomeDir()
	if err == nil && home != "" {
		candidate := filepath.Join(home, ".locksmith", "locksmith.sock")
		if _, err := os.Stat(candidate); err == nil {
			return candidate
		}
	}

	tmpCandidate := filepath.Join(os.TempDir(), fmt.Sprintf("locksmith-%d.sock", os.Getuid()))
	if _, err := os.Stat(tmpCandidate); err == nil {
		return tmpCandidate
	}

	defaultTmp := filepath.Join(os.TempDir(), "locksmith.sock")
	if _, err := os.Stat(defaultTmp); err == nil {
		return defaultTmp
	}

	if home != "" {
		return filepath.Join(home, ".locksmith", "locksmith.sock")
	}
	return defaultTmp
}

// Ping verifies whether the Locksmith daemon is alive and reachable.
func (c *LocksmithClient) Ping(ctx context.Context) error {
	conn, err := net.DialTimeout("unix", c.socketPath, 2*time.Second)
	if err != nil {
		return fmt.Errorf("airlock: failed to connect to Locksmith daemon at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	if err := json.NewEncoder(conn).Encode(map[string]any{
		"action": protocol.ActionPing,
	}); err != nil {
		return fmt.Errorf("airlock: failed to ping Locksmith daemon: %w", err)
	}

	var resp struct {
		Status string `json:"status"`
	}
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return fmt.Errorf("airlock: failed to read ping response: %w", err)
	}
	if resp.Status != "PONG" {
		return fmt.Errorf("airlock: unexpected ping status %q", resp.Status)
	}
	return nil
}

// RequestLease requests an ephemeral, single-use credential for the current process.
// It returns the response along with a mandatory cleanup closure that zeroes
// secret memory and revokes the lease with the Locksmith daemon.
func (c *LocksmithClient) RequestLease(ctx context.Context, secretName string, ttl time.Duration, sessionTicket string) (*protocol.LeaseResponse, func(), error) {
	identity, err := protocol.GetCurrentClientIdentity()
	if err != nil {
		return nil, nil, fmt.Errorf("airlock: failed to capture caller client identity: %w", err)
	}

	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, nil, fmt.Errorf("airlock: failed to connect to Locksmith daemon at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	req := &protocol.LeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRequestLease,
		ClientPID:        identity.PID,
		ProcessStartTime: identity.StartTime,
		ClientBinaryHash: identity.ExeHash,
		SecretName:       secretName,
		LeaseTTL:         ttl,
		MaxUses:          1,
		SessionTicket:    sessionTicket,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return nil, nil, fmt.Errorf("airlock: failed to dispatch lease request: %w", err)
	}

	var resp protocol.LeaseResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return nil, nil, fmt.Errorf("airlock: failed to decode lease response: %w", err)
	}

	if resp.Status != protocol.StatusGranted {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = string(resp.Status)
		}
		return nil, nil, fmt.Errorf("airlock: secret lease denied for %q: %s", secretName, errMsg)
	}

	leaseID := resp.LeaseID
	clientPID := identity.PID

	cleanup := func() {
		// 1. Zero out local secret bytes immediately
		resp.Zero()

		// 2. Dispatch revocation to Locksmith daemon
		if leaseID != "" {
			rConn, err := net.DialTimeout("unix", c.socketPath, 2*time.Second)
			if err == nil {
				defer rConn.Close()
				revokeReq := &protocol.RevokeRequest{
					Version:   protocol.ProtocolVersion,
					Action:    protocol.ActionRevokeLease,
					LeaseID:   leaseID,
					ClientPID: clientPID,
				}
				_ = json.NewEncoder(rConn).Encode(revokeReq)
			}
		}
	}

	return &resp, cleanup, nil
}

// CreateSession allocates a scoped session ticket allowing multiple sub-commands.
func (c *LocksmithClient) CreateSession(ctx context.Context, ttl time.Duration, allowedSecrets []string) (*protocol.SessionTicket, error) {
	var d net.Dialer
	conn, err := d.DialContext(ctx, "unix", c.socketPath)
	if err != nil {
		return nil, fmt.Errorf("airlock: failed to connect to Locksmith daemon at %s: %w", c.socketPath, err)
	}
	defer conn.Close()

	payload := map[string]any{
		"action":          protocol.ActionCreateSession,
		"pgid":            getProcessGroupID(),
		"ttl":             ttl,
		"allowed_secrets": allowedSecrets,
	}

	if err := json.NewEncoder(conn).Encode(payload); err != nil {
		return nil, fmt.Errorf("airlock: failed to dispatch session request: %w", err)
	}

	var ticket protocol.SessionTicket
	if err := json.NewDecoder(conn).Decode(&ticket); err != nil {
		return nil, fmt.Errorf("airlock: failed to decode session ticket: %w", err)
	}

	if ticket.TicketID == "" {
		return nil, errors.New("airlock: failed to allocate session ticket")
	}

	return &ticket, nil
}
