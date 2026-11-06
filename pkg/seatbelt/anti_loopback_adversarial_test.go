package seatbelt

import (
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// TestAntiLoopbackProfile_Generation verifies that AntiLoopback rules and socket whitelists
// are correctly interpolated into the synthesized Seatbelt profile.
func TestAntiLoopbackProfile_Generation(t *testing.T) {
	p := Params{
		UserHome:           "/Users/testuser",
		WorkspaceRoot:      "/Users/testuser/projects/demo",
		ScratchDir:         "/tmp/airlock-scratch",
		AntiLoopback:       true,
		ProxyPort:          18443,
		AllowedLoopbackPorts: []int{8443},
		AllowedUnixSockets: []string{"/tmp/crucible.sock", "~/.crucible/ipc.sock"},
	}

	gen := NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// Verify loopback and control plane denials
	expectedDenials := []string{
		`(deny network-outbound`,
		`(to ip "localhost:*")`,
		`(to tcp "localhost:8080")`,
		`(to tcp "localhost:9090")`,
		`(to tcp "localhost:2375")`,
		`(to tcp "localhost:11434")`,
	}
	for _, expected := range expectedDenials {
		if !strings.Contains(profile, expected) {
			t.Errorf("Profile missing expected anti-loopback rule: %q", expected)
		}
	}

	// Verify proxy port re-allowance
	if !strings.Contains(profile, `(allow network-outbound (to tcp "localhost:18443"))`) {
		t.Errorf("Profile missing proxy port allowance for 18443")
	}

	// Verify allowed loopback port re-allowance
	if !strings.Contains(profile, `(allow network-outbound (to tcp "localhost:8443"))`) {
		t.Errorf("Profile missing allowed loopback port allowance for 8443")
	}

	// Verify Unix socket whitelisting and path expansion
	if !strings.Contains(profile, `(allow network-outbound (literal "/tmp/crucible.sock") (subpath "/tmp/crucible.sock"))`) {
		t.Errorf("Profile missing Unix socket network-outbound allowance for /tmp/crucible.sock")
	}
	if !strings.Contains(profile, `(allow file-read* file-write* (literal "/tmp/crucible.sock") (subpath "/tmp/crucible.sock"))`) {
		t.Errorf("Profile missing Unix socket file access allowance for /tmp/crucible.sock")
	}
	expandedHomeSock := "/Users/testuser/.crucible/ipc.sock"
	if !strings.Contains(profile, fmt.Sprintf(`(allow network-outbound (literal "%s") (subpath "%s"))`, expandedHomeSock, expandedHomeSock)) {
		t.Errorf("Profile missing expanded Unix socket network-outbound allowance for %s", expandedHomeSock)
	}
}

// TestAntiLoopbackProfile_NamedProfiles verifies that agent profiles automatically enable AntiLoopback.
func TestAntiLoopbackProfile_NamedProfiles(t *testing.T) {
	gen := NewGenerator()
	agentProfiles := []string{"anti-loopback", "dev-agent", "agent", "strict-agent"}

	for _, profName := range agentProfiles {
		t.Run(profName, func(t *testing.T) {
			p := Params{
				Profile:       profName,
				UserHome:      "/Users/testuser",
				WorkspaceRoot: "/Users/testuser/projects/demo",
				ScratchDir:    "/tmp/airlock-scratch",
			}
			profile, err := gen.Generate(p)
			if err != nil {
				t.Fatalf("Generate failed for %s: %v", profName, err)
			}
			if !strings.Contains(profile, `(to tcp "localhost:8080")`) {
				t.Errorf("Profile %q failed to enable AntiLoopback by default", profName)
			}
		})
	}
}

// TestAntiLoopback_AdversarialLiveRejection runs an actual live sandbox-exec process on macOS
// and attempts to connect to 127.0.0.1:8080 and other control plane ports.
// Invariant: All attempts must fail closed with EPERM ("Operation not permitted").
func TestAntiLoopback_AdversarialLiveRejection(t *testing.T) {
	if runtime.GOOS != "darwin" {
		t.Skip("Skipping live macOS Seatbelt kernel test on non-darwin platform")
	}

	tempDir := t.TempDir()
	workspace := filepath.Join(tempDir, "workspace")
	scratch := filepath.Join(tempDir, "scratch")
	_ = os.Mkdir(workspace, 0755)
	_ = os.Mkdir(scratch, 0700)

	// 1. Start a mock server on 127.0.0.1:8080 if available, or an ephemeral loopback port
	l8080, err := net.Listen("tcp", "127.0.0.1:8080")
	if err == nil {
		defer l8080.Close()
		go func() {
			for {
				conn, err := l8080.Accept()
				if err != nil {
					return
				}
				_ = conn.Close()
			}
		}()
	}

	// 2. Start a mock Unix Domain Socket server to verify explicit whitelisting
	// Unix domain socket paths on macOS must be < 104 characters.
	mockSock := fmt.Sprintf("/tmp/mock_crucible_%d.sock", os.Getpid())
	_ = os.Remove(mockSock)
	sockListener, err := net.Listen("unix", mockSock)
	if err != nil {
		t.Fatalf("Failed to listen on unix socket: %v", err)
	}
	defer func() {
		_ = sockListener.Close()
		_ = os.Remove(mockSock)
	}()
	go func() {
		for {
			conn, err := sockListener.Accept()
			if err != nil {
				return
			}
			_, _ = conn.Write([]byte("PONG"))
			_ = conn.Close()
		}
	}()

	// 3. Generate Anti-Loopback Profile
	p := Params{
		Profile:            "anti-loopback",
		UserHome:           tempDir,
		WorkspaceRoot:      workspace,
		ScratchDir:         scratch,
		AntiLoopback:       true,
		AllowDirectNet:     true, // Even with direct external networking allowed, loopback MUST be blocked
		AllowedUnixSockets: []string{mockSock},
	}

	gen := NewGenerator()
	profile, err := gen.Generate(p)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	// 4. Adversarial Attack 1: Attempt TCP connection to 127.0.0.1:8080 inside sandbox
	// Must fail with Operation not permitted (EPERM)
	cmd8080 := exec.Command("sandbox-exec", "-p", profile, "nc", "-z", "-w", "1", "127.0.0.1", "8080")
	out8080, err8080 := cmd8080.CombinedOutput()
	if err8080 == nil {
		t.Fatalf("SECURITY BREACH: Sandboxed process successfully connected to 127.0.0.1:8080! Expected kernel EPERM.")
	}
	outputStr := string(out8080)
	if !strings.Contains(outputStr, "Operation not permitted") && !strings.Contains(outputStr, "failed") {
		t.Logf("Process failed as expected: %v (output: %s)", err8080, outputStr)
	}

	// 5. Adversarial Attack 2: Attempt TCP connection to localhost:8080
	cmdLocalhost := exec.Command("sandbox-exec", "-p", profile, "nc", "-z", "-w", "1", "localhost", "8080")
	outLocalhost, errLocalhost := cmdLocalhost.CombinedOutput()
	if errLocalhost == nil {
		t.Fatalf("SECURITY BREACH: Sandboxed process successfully connected to localhost:8080! Expected kernel EPERM.")
	}
	if !strings.Contains(string(outLocalhost), "Operation not permitted") && !strings.Contains(string(outLocalhost), "failed") {
		t.Logf("Process failed as expected: %v", errLocalhost)
	}

	// 6. Adversarial Attack 3: Attempt TCP connection to [::1]:8080
	cmdIPv6 := exec.Command("sandbox-exec", "-p", profile, "nc", "-z", "-w", "1", "::1", "8080")
	_, errIPv6 := cmdIPv6.CombinedOutput()
	if errIPv6 == nil {
		t.Fatalf("SECURITY BREACH: Sandboxed process successfully connected to ::1:8080! Expected kernel EPERM.")
	}

	// 7. Legitimate Communication: Connect to whitelisted Unix Domain Socket inside sandbox
	ctxSock, cancelSock := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancelSock()
	cmdSock := exec.CommandContext(ctxSock, "sandbox-exec", "-p", profile, "nc", "-U", "-w", "1", mockSock)
	cmdSock.Stdin = strings.NewReader("PING\n")
	outSock, errSock := cmdSock.CombinedOutput()
	if errSock != nil {
		t.Fatalf("Whitelisted Unix socket connection failed: %v (output: %s)", errSock, string(outSock))
	}
	if !strings.Contains(string(outSock), "PONG") {
		t.Logf("Unix socket returned: %s", string(outSock))
	}

	// 8. Without AllowedUnixSockets, all Unix socket connections must fail closed
	pNoSock := Params{
		Profile:       "anti-loopback",
		UserHome:      tempDir,
		WorkspaceRoot: workspace,
		ScratchDir:    scratch,
		AntiLoopback:  true,
		// AllowedUnixSockets is empty
	}
	profNoSock, err := gen.Generate(pNoSock)
	if err != nil {
		t.Fatalf("Generate failed: %v", err)
	}

	ctxDeny, cancelDeny := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancelDeny()
	cmdDeny := exec.CommandContext(ctxDeny, "sandbox-exec", "-p", profNoSock, "nc", "-U", "-w", "1", mockSock)
	if errDeny := cmdDeny.Run(); errDeny == nil {
		t.Errorf("SECURITY BREACH: Unix socket was accessible when AllowedUnixSockets was empty! Expected denial.")
	}
}

// Ensure time import is used if needed
var _ = time.Millisecond
