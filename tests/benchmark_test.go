package tests

import (
	"bufio"
	"context"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/vet"
)

// ----------------------------------------------------------------------------
// Benchmark 1: Sandbox Invocation Latency (Overhead SLA: < 15ms)
// ----------------------------------------------------------------------------

// BenchmarkBaseline_ExecCommand measures unconfined baseline process execution latency.
func BenchmarkBaseline_ExecCommand(b *testing.B) {
	cmdPath := "/usr/bin/true"
	if runtime.GOOS == "linux" {
		cmdPath = "/bin/true"
	}
	var args []string
	if runtime.GOOS == "windows" {
		cmdPath = "cmd.exe"
		args = []string{"/c", "exit 0"}
	} else if _, err := os.Stat(cmdPath); err != nil {
		cmdPath = "/bin/echo"
	}

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := exec.Command(cmdPath, args...)
		if err := cmd.Run(); err != nil {
			b.Fatalf("Baseline exec failed: %v", err)
		}
	}
}

// BenchmarkAirlock_SandboxInvocation measures Airlock sandboxed execution startup latency.
func BenchmarkAirlock_SandboxInvocation(b *testing.B) {
	tempDir := b.TempDir()
	cmdPath := "/usr/bin/true"
	if runtime.GOOS == "linux" {
		cmdPath = "/bin/true"
	}
	var execArgs []string
	if runtime.GOOS == "windows" {
		execArgs = []string{"cmd.exe", "/c", "exit 0"}
	} else {
		if _, err := os.Stat(cmdPath); err != nil {
			cmdPath = "/bin/echo"
		}
		execArgs = []string{cmdPath}
	}

	opts := sandbox.Options{
		WorkspaceRoot:  tempDir,
		Airgap:         true,
		NonInteractive: true,
		AuditLogger:    &audit.NopLogger{},
	}

	eng, err := sandbox.NewEngine(opts)
	if err != nil {
		b.Fatalf("Failed to initialize sandbox engine: %v", err)
	}

	ctx := context.Background()
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		code, err := eng.Execute(ctx, execArgs)
		if err != nil || code != 0 {
			b.Fatalf("Sandboxed execution failed (code: %d): %v", code, err)
		}
	}
}

// ----------------------------------------------------------------------------
// Benchmark 2: Ephemeral Forward Proxy Connection Latency & Throughput
// ----------------------------------------------------------------------------

// BenchmarkProxy_ConnectionLatency measures TCP connect + TLS CONNECT handshake latency.
func BenchmarkProxy_ConnectionLatency(b *testing.B) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	upstreamPort := listener.Addr().(*net.TCPAddr).Port
	upstreamHost := fmt.Sprintf("127.0.0.1:%d", upstreamPort)

	p, err := proxy.NewWithLogger([]string{"127.0.0.1"}, &audit.NopLogger{})
	if err != nil {
		b.Fatalf("Failed to initialize proxy: %v", err)
	}
	defer p.Close()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", p.Port())
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		dialer := net.Dialer{Timeout: 5 * time.Second}
		conn, err := dialer.Dial("tcp", proxyAddr)
		if err != nil {
			b.Fatalf("Failed to dial proxy: %v", err)
		}
		if tc, ok := conn.(*net.TCPConn); ok {
			_ = tc.SetLinger(0)
		}

		if _, err := conn.Write([]byte(connectReq)); err != nil {
			_ = conn.Close()
			b.Fatalf("Failed to send CONNECT request: %v", err)
		}

		reader := bufio.NewReader(conn)
		statusLine, err := reader.ReadString('\n')
		if err != nil || (!stringsContains(statusLine, "200") && !stringsContains(statusLine, "OK")) {
			_ = conn.Close()
			b.Fatalf("Unexpected proxy response: %s (err: %v)", statusLine, err)
		}

		_ = conn.Close()
	}
}

// BenchmarkProxy_DataThroughput measures raw streaming data transfer throughput through the proxy tunnel.
func BenchmarkProxy_DataThroughput(b *testing.B) {
	chunkSize := 64 * 1024 // 64 KB
	chunk := make([]byte, chunkSize)
	for i := range chunk {
		chunk[i] = byte(i % 256)
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		b.Fatalf("Failed to create test listener: %v", err)
	}
	defer listener.Close()

	go func() {
		for {
			conn, err := listener.Accept()
			if err != nil {
				return
			}
			go func(c net.Conn) {
				defer c.Close()
				buf := make([]byte, 32*1024)
				for {
					n, err := c.Read(buf)
					if err != nil {
						return
					}
					_, _ = c.Write(buf[:n])
				}
			}(conn)
		}
	}()

	upstreamPort := listener.Addr().(*net.TCPAddr).Port
	upstreamHost := fmt.Sprintf("127.0.0.1:%d", upstreamPort)

	p, err := proxy.NewWithLogger([]string{"127.0.0.1"}, &audit.NopLogger{})
	if err != nil {
		b.Fatalf("Failed to initialize proxy: %v", err)
	}
	defer p.Close()

	proxyAddr := fmt.Sprintf("127.0.0.1:%d", p.Port())
	connectReq := fmt.Sprintf("CONNECT %s HTTP/1.1\r\nHost: %s\r\n\r\n", upstreamHost, upstreamHost)

	conn, err := net.Dial("tcp", proxyAddr)
	if err != nil {
		b.Fatalf("Failed to dial proxy: %v", err)
	}
	defer conn.Close()

	if _, err := conn.Write([]byte(connectReq)); err != nil {
		b.Fatalf("Failed to send CONNECT request: %v", err)
	}

	reader := bufio.NewReader(conn)
	statusLine, err := reader.ReadString('\n')
	if err != nil || (!stringsContains(statusLine, "200") && !stringsContains(statusLine, "OK")) {
		b.Fatalf("CONNECT handshake failed: %s (err: %v)", statusLine, err)
	}
	// Consume blank line after headers
	_, _ = reader.ReadString('\n')

	recvBuf := make([]byte, chunkSize)
	b.SetBytes(int64(chunkSize))
	b.ResetTimer()

	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(chunk); err != nil {
			b.Fatalf("Failed to write data chunk: %v", err)
		}

		readTotal := 0
		for readTotal < chunkSize {
			n, err := conn.Read(recvBuf[readTotal:])
			if n > 0 {
				readTotal += n
			}
			if err != nil {
				b.Fatalf("Failed to read echoed data chunk: %v", err)
			}
		}
	}
}

// ----------------------------------------------------------------------------
// Benchmark 3: In-Process DNS Forwarder UDP Latency (SLA: < 5ms)
// ----------------------------------------------------------------------------

// BenchmarkDNS_ResolutionLatency measures UDP query-response round-trip latency.
func BenchmarkDNS_ResolutionLatency(b *testing.B) {
	allowed := map[string]bool{
		"registry.npmjs.org": true,
		"pypi.org":           true,
		"crates.io":          true,
	}

	dnsServer, err := proxy.NewDNSServer(allowed, &audit.NopLogger{})
	if err != nil {
		b.Fatalf("Failed to create DNS server: %v", err)
	}
	defer dnsServer.Close()

	dnsAddr := fmt.Sprintf("127.0.0.1:%d", dnsServer.Port())

	// Build raw DNS query for registry.npmjs.org
	// "registry" (8 bytes), "npmjs" (5 bytes), "org" (3 bytes)
	rawQuery := []byte{
		0xAB, 0xCD, // ID
		0x01, 0x00, // Standard query
		0x00, 0x01, // QDCOUNT: 1
		0x00, 0x00, 0x00, 0x00,
		0x08, 'r', 'e', 'g', 'i', 's', 't', 'r', 'y',
		0x05, 'n', 'p', 'm', 'j', 's',
		0x03, 'o', 'r', 'g',
		0x00,
		0x00, 0x01, // Type: A
		0x00, 0x01, // Class: IN
	}

	conn, err := net.Dial("udp", dnsAddr)
	if err != nil {
		b.Fatalf("Failed to dial UDP DNS: %v", err)
	}
	defer conn.Close()

	respBuf := make([]byte, 512)

	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		if _, err := conn.Write(rawQuery); err != nil {
			b.Fatalf("Failed to write DNS query: %v", err)
		}

		_ = conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
		n, err := conn.Read(respBuf)
		if err != nil || n < 12 {
			b.Fatalf("Failed to read DNS response (n=%d): %v", n, err)
		}
	}
}

// ----------------------------------------------------------------------------
// Benchmark 4: Argus Static Analysis Parsing Throughput (SLA: < 5ms per file)
// ----------------------------------------------------------------------------

// BenchmarkArgus_CommandInspection measures command string security evaluation latency.
func BenchmarkArgus_CommandInspection(b *testing.B) {
	engine := vet.NewEngine(vet.Config{
		StrictMode: true,
		Logger:     &audit.NopLogger{},
	})

	testCmds := [][]string{
		{"npm", "install", "express", "lodash", "react"},
		{"pip", "install", "requests", "numpy", "pandas"},
		{"cargo", "add", "serde", "tokio", "anyhow"},
		{"gem", "install", "rails", "puma"},
		{"go", "get", "github.com/gin-gonic/gin"},
	}

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		cmd := testCmds[i%len(testCmds)]
		_, _ = engine.Inspect(ctx, cmd, "")
	}
}

// BenchmarkArgus_ManifestFileInspection measures manifest parsing and static heuristic latency.
func BenchmarkArgus_ManifestFileInspection(b *testing.B) {
	tempDir := b.TempDir()

	// 1. package.json
	packageJSON := `{
  "name": "benchmark-app",
  "version": "1.0.0",
  "scripts": {
    "postinstall": "node scripts/setup.js",
    "test": "jest"
  },
  "dependencies": {
    "express": "^4.18.2",
    "lodash": "^4.17.21"
  }
}`
	_ = os.WriteFile(filepath.Join(tempDir, "package.json"), []byte(packageJSON), 0644)

	// 2. setup.py
	setupPy := `from setuptools import setup
setup(
    name="benchmark-pkg",
    version="0.1.0",
    packages=["benchmark"],
    install_requires=["requests>=2.28.0"],
)
`
	_ = os.WriteFile(filepath.Join(tempDir, "setup.py"), []byte(setupPy), 0644)

	// 3. Cargo.toml
	cargoToml := `[package]
name = "benchmark-rust"
version = "0.1.0"
edition = "2021"

[dependencies]
serde = { version = "1.0", features = ["derive"] }
tokio = { version = "1.0", features = ["full"] }
`
	_ = os.WriteFile(filepath.Join(tempDir, "Cargo.toml"), []byte(cargoToml), 0644)

	// 4. go.mod
	goMod := `module benchmark/mod

go 1.21

require (
	github.com/google/uuid v1.3.0
)
`
	_ = os.WriteFile(filepath.Join(tempDir, "go.mod"), []byte(goMod), 0644)

	engine := vet.NewEngine(vet.Config{
		StrictMode: true,
		Logger:     &audit.NopLogger{},
	})

	ctx := context.Background()
	b.ResetTimer()
	for i := 0; i < b.N; i++ {
		_, _ = engine.Inspect(ctx, nil, tempDir)
	}
}

func stringsContains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(substr) == 0 || (len(s) > 0 && len(substr) > 0 && stringSearch(s, substr)))
}

func stringSearch(s, substr string) bool {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
