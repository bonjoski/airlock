package secrets

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/protocol"
)

// ErrDaemonUnreachable indicates that the Locksmith Unix domain socket could not be dialed.
var ErrDaemonUnreachable = errors.New("airlock: locksmith daemon unreachable")

var safeEnvVarRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)

var forbiddenLeaseEnvVars = map[string]bool{
	"LD_PRELOAD":            true,
	"LD_LIBRARY_PATH":       true,
	"LD_AUDIT":              true,
	"DYLD_INSERT_LIBRARIES": true,
	"DYLD_LIBRARY_PATH":     true,
	"DYLD_FRAMEWORK_PATH":   true,
	"PATH":                  true,
	"HOME":                  true,
	"TMPDIR":                true,
	"IFS":                   true,
	"BASH_ENV":              true,
	"ENV":                   true,
	"NODE_OPTIONS":          true,
	"PYTHONPATH":            true,
	"RUBYOPT":               true,
	"PERL5OPT":              true,
	"GIT_SSH_COMMAND":       true,
}

func validateLeaseEnvVar(name string) error {
	if !safeEnvVarRe.MatchString(name) {
		return fmt.Errorf("airlock: invalid leased environment variable name %q", name)
	}
	upper := strings.ToUpper(name)
	if forbiddenLeaseEnvVars[upper] || strings.HasPrefix(upper, "LD_") || strings.HasPrefix(upper, "DYLD_") {
		return fmt.Errorf("airlock: refused forbidden leased environment variable %q", name)
	}
	return nil
}

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
	if sock := os.Getenv("LOCKSMITH_SOCK"); sock != "" {
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

// RedeemOpaqueLease exchanges an opaque lease handle with the local Locksmith UDS daemon.
// It returns the target environment variable name, raw secret bytes, and a mandatory cleanup
// function that zeroes secretBytes in place using clear(secretBytes).
func (c *LocksmithClient) RedeemOpaqueLease(ctx context.Context, leaseID, sessionID string) (string, []byte, func(), error) {
	leaseID = strings.TrimSpace(leaseID)
	if leaseID == "" {
		return "", nil, nil, errors.New("airlock: opaque lease_id cannot be empty")
	}
	if strings.TrimSpace(sessionID) == "" {
		sessionID = strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	}

	identity, err := protocol.GetCurrentClientIdentity()
	if err != nil {
		return "", nil, nil, fmt.Errorf("airlock: failed to capture caller client identity: %w", err)
	}

	dialCtx, cancel := withDefaultTimeout(ctx, 5*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", c.socketPath)
	if err != nil {
		return "", nil, nil, fmt.Errorf("%w at %s: %w", ErrDaemonUnreachable, c.socketPath, err)
	}
	defer conn.Close()

	if dl, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := &protocol.RedeemOpaqueLeaseRequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionRedeemOpaqueLease,
		LeaseID:          leaseID,
		SessionID:        sessionID,
		ClientPID:        identity.PID,
		ProcessStartTime: identity.StartTime,
		ClientBinaryHash: identity.ExeHash,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return "", nil, nil, fmt.Errorf("airlock: failed to dispatch opaque lease redemption: %w", err)
	}

	var resp protocol.RedeemOpaqueLeaseResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", nil, nil, fmt.Errorf("airlock: failed to decode opaque lease response: %w", err)
	}

	if resp.Status != protocol.StatusGranted {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = string(resp.Status)
		}
		if errMsg == "" {
			errMsg = "DENIED"
		}
		return "", nil, nil, fmt.Errorf("airlock: opaque lease redemption denied for %q: %s", leaseID, errMsg)
	}

	if err := validateLeaseEnvVar(resp.EnvVar); err != nil {
		return "", nil, nil, err
	}

	secretBytes, err := base64.StdEncoding.DecodeString(resp.SecretB64)
	if err != nil {
		return "", nil, nil, fmt.Errorf("airlock: failed to decode redeemed secret bytes: %w", err)
	}
	if len(secretBytes) == 0 {
		return "", nil, nil, errors.New("airlock: redeemed secret payload is empty")
	}

	cleanup := func() {
		clear(secretBytes)
	}

	return resp.EnvVar, secretBytes, cleanup, nil
}

// SignDSSE requests amortized session Ed25519 signing of a DSSE PAE byte slice
// over LOCKSMITH_SOCKET for BLPR-v1 receipt attestation.
func (c *LocksmithClient) SignDSSE(ctx context.Context, sessionID string, pae []byte) (string, []byte, error) {
	if len(pae) == 0 {
		return "", nil, errors.New("airlock: DSSE PAE payload cannot be empty")
	}
	if strings.TrimSpace(sessionID) == "" {
		sessionID = strings.TrimSpace(os.Getenv("FABRIAL_SESSION_ID"))
	}

	identity, err := protocol.GetCurrentClientIdentity()
	if err != nil {
		return "", nil, fmt.Errorf("airlock: failed to capture caller client identity: %w", err)
	}

	dialCtx, cancel := withDefaultTimeout(ctx, 2*time.Second)
	defer cancel()

	var d net.Dialer
	conn, err := d.DialContext(dialCtx, "unix", c.socketPath)
	if err != nil {
		return "", nil, fmt.Errorf("%w at %s: %w", ErrDaemonUnreachable, c.socketPath, err)
	}
	defer conn.Close()

	if dl, ok := dialCtx.Deadline(); ok {
		_ = conn.SetDeadline(dl)
	}

	req := &protocol.SignDSSERequest{
		Version:          protocol.ProtocolVersion,
		Action:           protocol.ActionSignDSSE,
		SessionID:        sessionID,
		PAEB64:           base64.StdEncoding.EncodeToString(pae),
		ClientPID:        identity.PID,
		ProcessStartTime: identity.StartTime,
		ClientBinaryHash: identity.ExeHash,
	}

	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return "", nil, fmt.Errorf("airlock: failed to dispatch sign_dsse request: %w", err)
	}

	var resp protocol.SignDSSEResponse
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return "", nil, fmt.Errorf("airlock: failed to decode sign_dsse response: %w", err)
	}

	if resp.Error != "" || resp.Status == protocol.StatusDenied || resp.Status == protocol.StatusRevoked || resp.Status == protocol.StatusExpired {
		errMsg := resp.Error
		if errMsg == "" {
			errMsg = string(resp.Status)
		}
		return "", nil, fmt.Errorf("airlock: sign_dsse denied by Locksmith: %s", errMsg)
	}

	keyID := resp.KeyID
	if keyID == "" {
		keyID = resp.KeyIDAlt
	}
	sigB64 := resp.SigB64
	if sigB64 == "" {
		sigB64 = resp.Sig
	}
	if keyID == "" || sigB64 == "" {
		return "", nil, errors.New("airlock: sign_dsse response missing keyid or signature")
	}

	sigBytes, err := base64.StdEncoding.DecodeString(sigB64)
	if err != nil {
		return "", nil, fmt.Errorf("airlock: failed to decode DSSE signature: %w", err)
	}
	if len(sigBytes) == 0 {
		return "", nil, errors.New("airlock: sign_dsse returned empty signature")
	}

	return keyID, sigBytes, nil
}

func withDefaultTimeout(ctx context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	if ctx == nil {
		return context.WithTimeout(context.Background(), d)
	}
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, d)
}
