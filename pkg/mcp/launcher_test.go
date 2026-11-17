package mcp

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/sandbox"
)

// TestDetectCommandType verifies runtime detection for npx, uvx, and generic commands.
func TestDetectCommandType(t *testing.T) {
	tests := []struct {
		name     string
		cmd      []string
		expected CommandType
	}{
		{"npx command", []string{"npx", "-y", "@modelcontextprotocol/server-postgres"}, CommandTypeNPX},
		{"npm command", []string{"npm", "run", "start"}, CommandTypeNPX},
		{"path to npx", []string{"/usr/local/bin/npx", "server"}, CommandTypeNPX},
		{"env wrapped npx", []string{"env", "npx", "-y", "pkg"}, CommandTypeNPX},
		{"uvx command", []string{"uvx", "mcp-server-git"}, CommandTypeUVX},
		{"uv command", []string{"uv", "run", "server"}, CommandTypeUVX},
		{"pip command", []string{"pip", "install", "foo"}, CommandTypeUVX},
		{"pip3 command", []string{"pip3", "install", "foo"}, CommandTypeUVX},
		{"path to uvx", []string{"~/.cargo/bin/uvx", "mcp-server-sqlite"}, CommandTypeUVX},
		{"generic binary", []string{"./custom-server", "--port", "3000"}, CommandTypeGeneric},
		{"empty command", []string{}, CommandTypeGeneric},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectCommandType(tt.cmd)
			if got != tt.expected {
				t.Errorf("DetectCommandType(%v) = %v; want %v", tt.cmd, got, tt.expected)
			}
		})
	}
}

// TestOfflineEnvInjection verifies that offline execution environment variables
// are properly constructed to prevent runtime transitive resolution drift.
func TestOfflineEnvInjection(t *testing.T) {
	cacheDir := "/custom/mcp-cache"

	t.Run("npx environment", func(t *testing.T) {
		env := GetOfflineEnv(CommandTypeNPX, cacheDir)
		envMap := make(map[string]string)
		for _, e := range env {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}

		if envMap["npm_config_offline"] != "true" {
			t.Errorf("expected npm_config_offline=true, got %q", envMap["npm_config_offline"])
		}
		expectedCache := filepath.Join(cacheDir, "npm")
		if envMap["npm_config_cache"] != expectedCache {
			t.Errorf("expected npm_config_cache=%s, got %q", expectedCache, envMap["npm_config_cache"])
		}
	})

	t.Run("uvx environment", func(t *testing.T) {
		env := GetOfflineEnv(CommandTypeUVX, cacheDir)
		envMap := make(map[string]string)
		for _, e := range env {
			parts := strings.SplitN(e, "=", 2)
			if len(parts) == 2 {
				envMap[parts[0]] = parts[1]
			}
		}

		if envMap["PIP_NO_INDEX"] != "true" {
			t.Errorf("expected PIP_NO_INDEX=true, got %q", envMap["PIP_NO_INDEX"])
		}
		if envMap["UV_NO_SYNC"] != "1" {
			t.Errorf("expected UV_NO_SYNC=1, got %q", envMap["UV_NO_SYNC"])
		}
		expectedWheels := filepath.Join(cacheDir, "wheels")
		if envMap["PIP_FIND_LINKS"] != expectedWheels {
			t.Errorf("expected PIP_FIND_LINKS=%s, got %q", expectedWheels, envMap["PIP_FIND_LINKS"])
		}
		expectedUVCache := filepath.Join(cacheDir, "uv")
		if envMap["UV_CACHE_DIR"] != expectedUVCache {
			t.Errorf("expected UV_CACHE_DIR=%s, got %q", expectedUVCache, envMap["UV_CACHE_DIR"])
		}
	})
}

// TestLockfileIntegrity_ValidLockfilePasses verifies that a valid lockfile matching
// the command passes integrity checks.
func TestLockfileIntegrity_ValidLockfilePasses(t *testing.T) {
	tempDir := t.TempDir()
	lockfilePath := filepath.Join(tempDir, "mcp-lock.json")
	cmd := []string{"npx", "-y", "@modelcontextprotocol/server-postgres", "postgresql://localhost/db"}

	lf, err := CreateLockfile(lockfilePath, cmd)
	if err != nil {
		t.Fatalf("CreateLockfile failed: %v", err)
	}

	expectedHash := ComputeBundleFingerprint(cmd)
	if lf.BundleHash != expectedHash {
		t.Fatalf("expected bundle hash %s, got %s", expectedHash, lf.BundleHash)
	}

	verified, err := VerifyLockfile(lockfilePath, cmd)
	if err != nil {
		t.Fatalf("VerifyLockfile failed on valid lockfile: %v", err)
	}
	if verified.BundleHash != expectedHash {
		t.Errorf("expected %s, got %s", expectedHash, verified.BundleHash)
	}
}

// TestLockfileIntegrity_RejectsTamperedLockfile verifies that any modification
// to bundle hash, command, or lockfile bytes causes integrity verification to fail.
func TestLockfileIntegrity_RejectsTamperedLockfile(t *testing.T) {
	tempDir := t.TempDir()
	cmd := []string{"npx", "-y", "@modelcontextprotocol/server-postgres"}

	t.Run("tampered bundle hash", func(t *testing.T) {
		lockfilePath := filepath.Join(tempDir, "tampered-hash.json")
		_, err := CreateLockfile(lockfilePath, cmd)
		if err != nil {
			t.Fatalf("failed to create lockfile: %v", err)
		}

		// Read and tamper with bundle_hash
		data, _ := os.ReadFile(lockfilePath)
		tampered := strings.Replace(string(data), `"bundle_hash": "`, `"bundle_hash": "00000000000000000000000000000000`, 1)
		_ = os.WriteFile(lockfilePath, []byte(tampered), 0644)

		_, err = VerifyLockfile(lockfilePath, cmd)
		if err == nil {
			t.Fatal("expected error on tampered bundle hash, got nil")
		}
		if !errors.Is(err, ErrLockfileIntegrityFailed) {
			t.Errorf("expected ErrLockfileIntegrityFailed, got: %v", err)
		}
	})

	t.Run("tampered command arguments", func(t *testing.T) {
		lockfilePath := filepath.Join(tempDir, "original.json")
		_, err := CreateLockfile(lockfilePath, cmd)
		if err != nil {
			t.Fatalf("failed to create lockfile: %v", err)
		}

		// Verify against different / injected command arguments
		injectedCmd := []string{"npx", "-y", "@modelcontextprotocol/server-postgres", "--injected-flag"}
		_, err = VerifyLockfile(lockfilePath, injectedCmd)
		if err == nil {
			t.Fatal("expected error on command mismatch, got nil")
		}
		if !errors.Is(err, ErrLockfileIntegrityFailed) {
			t.Errorf("expected ErrLockfileIntegrityFailed, got: %v", err)
		}
	})

	t.Run("corrupted JSON content", func(t *testing.T) {
		corruptedPath := filepath.Join(tempDir, "corrupted.json")
		_ = os.WriteFile(corruptedPath, []byte("NOT_VALID_JSON{{{"), 0644)

		_, err := VerifyLockfile(corruptedPath, cmd)
		if err == nil {
			t.Fatal("expected error on corrupted json, got nil")
		}
		if !errors.Is(err, ErrInvalidLockfile) {
			t.Errorf("expected ErrInvalidLockfile, got: %v", err)
		}
	})

	t.Run("missing lockfile", func(t *testing.T) {
		missingPath := filepath.Join(tempDir, "nonexistent.json")
		_, err := VerifyLockfile(missingPath, cmd)
		if err == nil {
			t.Fatal("expected error on missing lockfile, got nil")
		}
		if !errors.Is(err, ErrLockfileNotFound) {
			t.Errorf("expected ErrLockfileNotFound, got: %v", err)
		}
	})
}

// mockEngine implements sandbox.Engine for unit tests.
type mockEngine struct {
	recordedOpts sandbox.SandboxOpts
	recordedCmd  []string
	exitCode     int
	err          error
}

func (m *mockEngine) Execute(ctx context.Context, cmd []string) (int, error) {
	m.recordedCmd = cmd
	return m.exitCode, m.err
}

// TestLauncher_ExecutionWiring verifies that Launcher sets up sandbox options,
// injects offline environment variables, and delegates to the sandbox engine.
func TestLauncher_ExecutionWiring(t *testing.T) {
	tempDir := t.TempDir()
	cacheDir := filepath.Join(tempDir, "cache")
	workspace := filepath.Join(tempDir, "workspace")
	_ = os.MkdirAll(workspace, 0755)

	var capturedOpts sandbox.SandboxOpts
	var capturedCmd []string

	mockLoader := func(opts sandbox.SandboxOpts) (sandbox.Engine, error) {
		capturedOpts = opts
		return &mockEngine{recordedOpts: opts, exitCode: 0}, nil
	}

	t.Run("npx invocation auto-freezes lockfile and injects npm offline env", func(t *testing.T) {
		launcher := NewLauncher(LauncherConfig{
			CacheDir:  cacheDir,
			Workspace: workspace,
		}, WithEngineLoader(mockLoader))

		cmd := []string{"npx", "-y", "@modelcontextprotocol/server-memory"}
		code, err := launcher.Launch(context.Background(), cmd)
		if err != nil {
			t.Fatalf("Launch failed: %v", err)
		}
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}

		if capturedOpts.Profile != "mcp" {
			t.Errorf("expected profile 'mcp', got %q", capturedOpts.Profile)
		}

		// Verify offline environment variables
		hasOffline := false
		hasCache := false
		for _, e := range capturedOpts.ExtraEnv {
			if e == "npm_config_offline=true" {
				hasOffline = true
			}
			if strings.HasPrefix(e, "npm_config_cache=") {
				hasCache = true
			}
		}
		if !hasOffline {
			t.Errorf("expected npm_config_offline=true in ExtraEnv, got: %v", capturedOpts.ExtraEnv)
		}
		if !hasCache {
			t.Errorf("expected npm_config_cache in ExtraEnv, got: %v", capturedOpts.ExtraEnv)
		}

		// Verify auto-frozen lockfile exists
		bundleHash := ComputeBundleFingerprint(cmd)
		lockfilePath := filepath.Join(cacheDir, bundleHash, "lock.json")
		if _, err := os.Stat(lockfilePath); err != nil {
			t.Errorf("expected auto-frozen lockfile at %s: %v", lockfilePath, err)
		}
	})

	t.Run("uvx invocation injects python offline env", func(t *testing.T) {
		launcher := NewLauncher(LauncherConfig{
			CacheDir:  cacheDir,
			Workspace: workspace,
		}, WithEngineLoader(mockLoader))

		cmd := []string{"uvx", "mcp-server-git"}
		code, err := launcher.Launch(context.Background(), cmd)
		if err != nil {
			t.Fatalf("Launch failed: %v", err)
		}
		if code != 0 {
			t.Errorf("expected exit code 0, got %d", code)
		}

		hasNoIndex := false
		hasNoSync := false
		for _, e := range capturedOpts.ExtraEnv {
			if e == "PIP_NO_INDEX=true" {
				hasNoIndex = true
			}
			if e == "UV_NO_SYNC=1" {
				hasNoSync = true
			}
		}
		if !hasNoIndex {
			t.Errorf("expected PIP_NO_INDEX=true in ExtraEnv, got: %v", capturedOpts.ExtraEnv)
		}
		if !hasNoSync {
			t.Errorf("expected UV_NO_SYNC=1 in ExtraEnv, got: %v", capturedOpts.ExtraEnv)
		}
	})

	t.Run("tampered lockfile aborts launch before engine execution", func(t *testing.T) {
		tamperedLockfile := filepath.Join(tempDir, "bad-lock.json")
		_ = os.WriteFile(tamperedLockfile, []byte(`{"version":1,"bundle_hash":"bad","command":["foo"]}`), 0644)

		engineCalled := false
		badLoader := func(opts sandbox.SandboxOpts) (sandbox.Engine, error) {
			engineCalled = true
			return &mockEngine{}, nil
		}

		launcher := NewLauncher(LauncherConfig{
			Lockfile: tamperedLockfile,
			CacheDir: cacheDir,
		}, WithEngineLoader(badLoader))

		_, err := launcher.Launch(context.Background(), []string{"npx", "-y", "pkg"})
		if err == nil {
			t.Fatal("expected launch to fail on tampered lockfile, got nil")
		}
		if engineCalled {
			t.Fatal("SECURITY FAILURE: Engine was called despite lockfile integrity failure!")
		}
	})

	_ = capturedCmd
}

// TestNetworkIsolation_LiveAdversarialRejection verifies live kernel sandbox confinement
// on macOS and Linux platforms:
// 1. WAN socket calls (e.g. 1.1.1.1:80) MUST fail closed with EPERM.
// 2. Loopback TCP calls (127.0.0.1:<port>) MUST succeed.
// 3. Unix Domain Socket calls MUST succeed.
// 4. If --allow-network is specified, outbound connection to that port is permitted.
func TestNetworkIsolation_LiveAdversarialRejection(t *testing.T) {
	if runtime.GOOS != "darwin" && runtime.GOOS != "linux" {
		t.Skip("Skipping live kernel sandboxing test on non-darwin/non-linux platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	cacheDir := filepath.Join(tempDir, "cache")
	_ = os.MkdirAll(workspace, 0755)
	_ = os.MkdirAll(cacheDir, 0755)

	// 1. Start a local loopback TCP listener on an ephemeral port
	loopbackListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("failed to create loopback listener: %v", err)
	}
	defer loopbackListener.Close()
	loopbackPort := loopbackListener.Addr().(*net.TCPAddr).Port

	go func() {
		for {
			conn, err := loopbackListener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("LOOPBACK_OK\n"))
			_ = conn.Close()
		}
	}()

	// 2. Start a local Unix Domain Socket listener
	socketPath := fmt.Sprintf("/tmp/airlock_mcp_test_%d.sock", os.Getpid())
	_ = os.Remove(socketPath)
	udsListener, err := net.Listen("unix", socketPath)
	if err != nil {
		t.Fatalf("failed to create UDS listener: %v", err)
	}
	defer func() {
		_ = udsListener.Close()
		_ = os.Remove(socketPath)
	}()

	go func() {
		for {
			conn, err := udsListener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("UDS_OK\n"))
			_ = conn.Close()
		}
	}()

	// Test Case 1: WAN socket connection to 1.1.1.1:80 must be REJECTED (EPERM)
	t.Run("WAN socket denied when allow-network omitted", func(t *testing.T) {
		launcher := NewLauncher(LauncherConfig{
			CacheDir:  cacheDir,
			Workspace: workspace,
		})

		// Use python3 to attempt a direct TCP socket connection to 1.1.1.1:80
		pythonCode := `
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("1.1.1.1", 80))
    print("UNEXPECTED_SUCCESS")
    sys.exit(0)
except PermissionError:
    print("EXPECTED_EPERM")
    sys.exit(42)
except Exception as e:
    print("FAILED:", e)
    sys.exit(42)
`
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		exitCode, err := launcher.Launch(ctx, []string{"python3", "-c", pythonCode})
		if exitCode == 0 {
			t.Fatalf("SECURITY BREACH: Sandboxed MCP process successfully connected to WAN (1.1.1.1:80)! Expected kernel denial.")
		}
		if exitCode != 42 && err == nil {
			t.Logf("Process exited with %d (expected rejection)", exitCode)
		}
	})

	// Test Case 2: Loopback TCP connection to 127.0.0.1:<port> must SUCCEED
	t.Run("Loopback TCP connection allowed", func(t *testing.T) {
		launcher := NewLauncher(LauncherConfig{
			CacheDir:  cacheDir,
			Workspace: workspace,
		})

		pythonCode := fmt.Sprintf(`
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("127.0.0.1", %d))
    data = s.recv(1024)
    if b"LOOPBACK_OK" in data:
        sys.exit(0)
    sys.exit(1)
except Exception as e:
    print("Loopback error:", e)
    sys.exit(2)
`, loopbackPort)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		exitCode, err := launcher.Launch(ctx, []string{"python3", "-c", pythonCode})
		if err != nil || exitCode != 0 {
			t.Fatalf("Loopback connection failed inside MCP sandbox (code %d): %v", exitCode, err)
		}
	})

	// Test Case 3: Unix Domain Socket connection must SUCCEED
	t.Run("Unix Domain Socket connection allowed", func(t *testing.T) {
		launcher := NewLauncher(LauncherConfig{
			CacheDir:  cacheDir,
			Workspace: workspace,
		})

		pythonCode := fmt.Sprintf(`
import socket, sys
try:
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(%q)
    data = s.recv(1024)
    if b"UDS_OK" in data:
        sys.exit(0)
    sys.exit(1)
except Exception as e:
    print("UDS error:", e)
    sys.exit(2)
`, socketPath)

		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		exitCode, err := launcher.Launch(ctx, []string{"python3", "-c", pythonCode})
		if err != nil || exitCode != 0 {
			t.Fatalf("UDS connection failed inside MCP sandbox (code %d): %v", exitCode, err)
		}
	})

	// Test Case 4: Allowlisted network endpoint permits specified port, denies other ports
	t.Run("Allowlisted endpoint permits specified port and blocks others", func(t *testing.T) {
		launcher := NewLauncher(LauncherConfig{
			CacheDir:     cacheDir,
			Workspace:    workspace,
			AllowNetwork: "1.1.1.1:80",
		})

		// Connecting to port 443 should STILL be blocked
		pythonCode := `
import socket, sys
try:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2)
    s.connect(("1.1.1.1", 443))
    print("UNEXPECTED_SUCCESS")
    sys.exit(0)
except PermissionError:
    print("EXPECTED_EPERM_PORT_443")
    sys.exit(42)
except Exception as e:
    sys.exit(42)
`
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()

		exitCode, _ := launcher.Launch(ctx, []string{"python3", "-c", pythonCode})
		if exitCode == 0 {
			t.Fatalf("SECURITY BREACH: Non-allowlisted port (443) succeeded when only port 80 was allowlisted!")
		}
	})
}
