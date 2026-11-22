package mcp

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/secrets"
	"github.com/bonjoski/airlock/pkg/version"
)

// BLPR-v1 / in-toto Statement v1 / DSSE constants (RFC-2026-11-22-49).
const (
	StatementTypeV1   = "https://in-toto.io/Statement/v1"
	PredicateTypeV1   = "https://bonjoski.dev/attestation/paved-road/v1"
	DSSEPayloadType   = "application/vnd.in-toto+json"
	BLPRSchemaVersion = "1.0.0"
)

// Verdict represents the outcome attested by a BLPR-v1 receipt.
type Verdict string

const (
	VerdictAllow Verdict = "allow"
	VerdictDeny  Verdict = "deny"
	VerdictWarn  Verdict = "warn"
)

// ErrReceiptSymlinkPolicy indicates a symlinked or untrusted receipt directory was rejected fail-closed.
var ErrReceiptSymlinkPolicy = errors.New("airlock: receipt directory rejected by non-symlink policy")

// Subject identifies the hashed target artifact or command of a BLPR-v1 statement.
type Subject struct {
	Name   string            `json:"name"`
	Digest map[string]string `json:"digest"`
}

// SessionLineage correlates the receipt with the active Fabrial session and worktree.
type SessionLineage struct {
	SessionID       string `json:"session_id"`
	ParentSessionID string `json:"parent_session_id,omitempty"`
	ActorMode       string `json:"actor_mode"`
	WorktreeHeadSHA string `json:"worktree_head_sha"`
}

// Producer identifies the sovereign tool that generated the receipt.
type Producer struct {
	Tool    string `json:"tool"`
	Version string `json:"version"`
	Stage   string `json:"stage"`
}

// Predicate carries the Bonjoski Local Provenance Receipt v1 payload.
type Predicate struct {
	SchemaVersion  string          `json:"schema_version"`
	ReceiptID      string          `json:"receipt_id"`
	Timestamp      string          `json:"timestamp"`
	Session        SessionLineage  `json:"session"`
	Producer       Producer        `json:"producer"`
	Verdict        Verdict         `json:"verdict"`
	Proven         bool            `json:"proven"`
	Claims         json.RawMessage `json:"claims"`
	ParentReceipts []string        `json:"parent_receipts,omitempty"`
	FixForwardCode string          `json:"fix_forward_code,omitempty"`
}

// Statement is an in-toto Statement v1 payload conforming to blpr-v1.schema.json.
type Statement struct {
	Type          string    `json:"_type"`
	Subject       []Subject `json:"subject"`
	PredicateType string    `json:"predicateType"`
	Predicate     Predicate `json:"predicate"`
}

// DSSESignature is a single cryptographic signature entry in a DSSE envelope.
type DSSESignature struct {
	KeyID string `json:"keyid"`
	Sig   string `json:"sig"`
}

// DSSEEnvelope wraps a base64-encoded in-toto Statement v1 with DSSE signatures.
type DSSEEnvelope struct {
	PayloadType string          `json:"payloadType"`
	Payload     string          `json:"payload"`
	Signatures  []DSSESignature `json:"signatures"`
}

// PAE computes the DSSE Pre-Authentication Encoding per spec:
// "DSSEv1 " + len(type) + " " + type + " " + len(body) + " " + body
func PAE(payloadType string, payload []byte) []byte {
	prefix := fmt.Sprintf("DSSEv1 %d %s %d ", len(payloadType), payloadType, len(payload))
	out := make([]byte, 0, len(prefix)+len(payload))
	out = append(out, prefix...)
	out = append(out, payload...)
	return out
}

// ReceiptParams configures BLPR-v1 receipt generation and atomic persistence.
type ReceiptParams struct {
	ReceiptDir      string
	WorkspaceRoot   string
	SessionID       string
	SubjectName     string
	SubjectData     []byte
	Verdict         Verdict
	Claims          map[string]any
	FixForwardCode  string
	LocksmithSocket string
}

var (
	validSessionIDRe = regexp.MustCompile(`^sess_[0-9A-Za-z]+$`)
	validGitSHARe    = regexp.MustCompile(`^[a-f0-9]{7,64}$`)
)

// GenerateReceiptID generates a CSPRNG receipt identifier matching ^rcpt_[0-9A-Za-z]+$.
func GenerateReceiptID() string {
	var raw [12]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Sprintf("rcpt_%d", time.Now().UTC().UnixNano())
	}
	return "rcpt_" + hex.EncodeToString(raw[:])
}

func normalizeBLPRSessionID(sessionID string) (string, error) {
	s := strings.TrimSpace(sessionID)
	if s == "" {
		return "sess_local000000", nil
	}
	if strings.ContainsAny(s, "/\\\x00") || strings.Contains(s, "..") {
		return "", fmt.Errorf("%w: invalid session_id %q", ErrReceiptSymlinkPolicy, s)
	}
	if validSessionIDRe.MatchString(s) {
		return s, nil
	}
	var b strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		}
	}
	cleaned := b.String()
	if cleaned == "" {
		return "", fmt.Errorf("%w: invalid session_id %q", ErrReceiptSymlinkPolicy, s)
	}
	if strings.HasPrefix(cleaned, "sess") && len(cleaned) > 4 {
		return "sess_" + cleaned[4:], nil
	}
	return "sess_" + cleaned, nil
}

// ValidateReceiptDir verifies that receiptDir (and its immediate parent / workspace-relative path)
// is not a symlink and safely creates the directory with 0700 permissions if absent.
func ValidateReceiptDir(receiptDir, workspaceRoot string) error {
	cleanDir := filepath.Clean(strings.TrimSpace(receiptDir))
	if cleanDir == "" || cleanDir == "." || cleanDir == string(filepath.Separator) {
		return fmt.Errorf("%w: empty or root receipt directory", ErrReceiptSymlinkPolicy)
	}

	// 1. Reject direct symlink on receiptDir via Lstat
	if fi, err := os.Lstat(cleanDir); err == nil {
		if fi.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("%w: %q is a symlink", ErrReceiptSymlinkPolicy, cleanDir)
		}
		if !fi.IsDir() {
			return fmt.Errorf("%w: %q is not a directory", ErrReceiptSymlinkPolicy, cleanDir)
		}
	} else if !os.IsNotExist(err) {
		return fmt.Errorf("%w: cannot inspect %q: %w", ErrReceiptSymlinkPolicy, cleanDir, err)
	}

	// 2. Reject symlink on immediate parent directory (unless system root alias like /var or /tmp on macOS)
	parent := filepath.Dir(cleanDir)
	if parent != cleanDir && !isSystemRootAlias(parent) {
		if pfi, err := os.Lstat(parent); err == nil {
			if pfi.Mode()&os.ModeSymlink != 0 {
				return fmt.Errorf("%w: parent directory %q is a symlink", ErrReceiptSymlinkPolicy, parent)
			}
		}
	}

	// 3. If receiptDir is syntactically inside workspaceRoot, verify no intermediate component is a symlink
	if workspaceRoot != "" {
		cleanWS := filepath.Clean(workspaceRoot)
		if rel, err := filepath.Rel(cleanWS, cleanDir); err == nil && rel != "." && !strings.HasPrefix(rel, "..") {
			curr := cleanWS
			for _, part := range strings.Split(rel, string(filepath.Separator)) {
				if part == "" || part == "." {
					continue
				}
				curr = filepath.Join(curr, part)
				if cfi, err := os.Lstat(curr); err == nil {
					if cfi.Mode()&os.ModeSymlink != 0 {
						return fmt.Errorf("%w: workspace path component %q is a symlink", ErrReceiptSymlinkPolicy, curr)
					}
				}
			}
		}
	}

	// 4. Create if missing (0700) after verifying parent safety
	if _, err := os.Lstat(cleanDir); os.IsNotExist(err) {
		if err := os.MkdirAll(cleanDir, 0700); err != nil {
			return fmt.Errorf("failed to create receipt directory %q: %w", cleanDir, err)
		}
	}

	// 5. Kernel-enforced O_NOFOLLOW + O_DIRECTORY + owner UID verification
	if err := verifyDirNoFollow(cleanDir); err != nil {
		return fmt.Errorf("%w: %v", ErrReceiptSymlinkPolicy, err)
	}

	return nil
}

func isSystemRootAlias(p string) bool {
	return p == "/" || p == "/var" || p == "/tmp" || p == "/etc"
}

// EmitReceipt creates, signs (via LOCKSMITH_SOCKET when reachable), and atomically writes
// a BLPR-v1 DSSE/in-toto Statement v1 receipt under params.ReceiptDir using os.OpenRoot.
func EmitReceipt(ctx context.Context, params ReceiptParams) (string, string, error) {
	if strings.TrimSpace(params.ReceiptDir) == "" {
		return "", "", nil
	}
	if err := ValidateReceiptDir(params.ReceiptDir, params.WorkspaceRoot); err != nil {
		return "", "", err
	}

	normSessionID, err := normalizeBLPRSessionID(params.SessionID)
	if err != nil {
		return "", "", err
	}

	receiptID := GenerateReceiptID()
	digest := sha256.Sum256(params.SubjectData)
	subjectName := strings.TrimSpace(params.SubjectName)
	if subjectName == "" {
		subjectName = "airlock-exec"
	}
	if len(subjectName) > 512 {
		subjectName = subjectName[:512]
	}

	claims := make(map[string]any, len(params.Claims)+1)
	for k, v := range params.Claims {
		claims[k] = v
	}

	headSHA := resolveWorktreeHeadSHA(params.WorkspaceRoot)
	ver := strings.TrimSpace(version.Version)
	if ver == "" {
		ver = "0.12.0"
	}

	buildStatement := func(proven bool, sigMode string) ([]byte, error) {
		claims["signature_mode"] = sigMode
		claimsRaw, err := json.Marshal(claims)
		if err != nil {
			return nil, err
		}
		stmt := Statement{
			Type: StatementTypeV1,
			Subject: []Subject{
				{
					Name:   subjectName,
					Digest: map[string]string{"sha256": hex.EncodeToString(digest[:])},
				},
			},
			PredicateType: PredicateTypeV1,
			Predicate: Predicate{
				SchemaVersion: BLPRSchemaVersion,
				ReceiptID:     receiptID,
				Timestamp:     time.Now().UTC().Format(time.RFC3339),
				Session: SessionLineage{
					SessionID:       normSessionID,
					ActorMode:       "aidlc",
					WorktreeHeadSHA: headSHA,
				},
				Producer: Producer{
					Tool:    "airlock",
					Version: ver,
					Stage:   "scaffolding_deps",
				},
				Verdict:        params.Verdict,
				Proven:         proven,
				Claims:         claimsRaw,
				FixForwardCode: params.FixForwardCode,
			},
		}
		return json.Marshal(stmt)
	}

	payloadBytes, err := buildStatement(true, "ed25519_locksmith")
	if err != nil {
		return "", "", fmt.Errorf("marshal BLPR-v1 statement: %w", err)
	}

	lsClient := secrets.NewLocksmithClient(params.LocksmithSocket)
	pae := PAE(DSSEPayloadType, payloadBytes)
	keyID, sigBytes, signErr := lsClient.SignDSSE(ctx, normSessionID, pae)

	var signatures []DSSESignature
	if signErr == nil {
		signatures = []DSSESignature{
			{
				KeyID: keyID,
				Sig:   base64.StdEncoding.EncodeToString(sigBytes),
			},
		}
	} else if errors.Is(signErr, secrets.ErrDaemonUnreachable) && os.Getenv("AIRLOCK_REQUIRE_SIGNED_RECEIPTS") != "1" {
		// Graceful unsigned local mode when no Locksmith daemon is running (e.g. unit tests)
		payloadBytes, err = buildStatement(false, "unsigned_local")
		if err != nil {
			return "", "", fmt.Errorf("marshal unsigned BLPR-v1 statement: %w", err)
		}
		signatures = []DSSESignature{}
	} else {
		return "", "", fmt.Errorf("BLPR-v1 receipt signing failed: %w", signErr)
	}

	env := DSSEEnvelope{
		PayloadType: DSSEPayloadType,
		Payload:     base64.StdEncoding.EncodeToString(payloadBytes),
		Signatures:  signatures,
	}
	envBytes, err := json.MarshalIndent(env, "", "  ")
	if err != nil {
		return "", "", fmt.Errorf("marshal BLPR-v1 envelope: %w", err)
	}
	envBytes = append(envBytes, '\n')

	root, err := os.OpenRoot(params.ReceiptDir)
	if err != nil {
		return "", "", fmt.Errorf("open receipt root %q: %w", params.ReceiptDir, err)
	}
	defer root.Close()

	tmpName := fmt.Sprintf(".tmp-%s.dsse.json", receiptID)
	finalName := fmt.Sprintf("%d-airlock-%s.dsse.json", time.Now().UTC().UnixMilli(), receiptID)

	f, err := root.OpenFile(tmpName, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return "", "", fmt.Errorf("create temp receipt file: %w", err)
	}
	if _, err := f.Write(envBytes); err != nil {
		_ = f.Close()
		_ = root.Remove(tmpName)
		return "", "", fmt.Errorf("write temp receipt file: %w", err)
	}
	if err := f.Sync(); err != nil {
		_ = f.Close()
		_ = root.Remove(tmpName)
		return "", "", fmt.Errorf("sync temp receipt file: %w", err)
	}
	if err := f.Close(); err != nil {
		_ = root.Remove(tmpName)
		return "", "", fmt.Errorf("close temp receipt file: %w", err)
	}
	if err := root.Rename(tmpName, finalName); err != nil {
		_ = root.Remove(tmpName)
		return "", "", fmt.Errorf("atomic rename receipt file: %w", err)
	}

	return receiptID, filepath.Join(params.ReceiptDir, finalName), nil
}

func resolveWorktreeHeadSHA(workspaceRoot string) string {
	if workspaceRoot != "" {
		cmd := exec.Command("git", "-C", workspaceRoot, "rev-parse", "HEAD")
		if out, err := cmd.Output(); err == nil {
			sha := strings.TrimSpace(string(out))
			if validGitSHARe.MatchString(sha) {
				return sha
			}
		}
	}
	return "0000000"
}
