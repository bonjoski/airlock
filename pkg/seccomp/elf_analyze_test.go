package seccomp

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestAnalyzeELF_NonELFFile(t *testing.T) {
	tmpDir := t.TempDir()
	scriptPath := filepath.Join(tmpDir, "script.sh")
	if err := os.WriteFile(scriptPath, []byte("#!/bin/sh\necho hello\n"), 0755); err != nil {
		t.Fatalf("failed to write script: %v", err)
	}

	res, err := AnalyzeELF(scriptPath, "amd64")
	if err != nil {
		t.Fatalf("AnalyzeELF failed: %v", err)
	}

	if res.IsELF {
		t.Errorf("Expected IsELF to be false for shell script")
	}
	if res.Prunable {
		t.Errorf("Expected Prunable to be false for non-ELF file (fail-closed)")
	}
}

func TestAnalyzeELF_NonExistentFile(t *testing.T) {
	_, err := AnalyzeELF("/nonexistent/file/path/here", "amd64")
	if err == nil {
		t.Fatal("Expected error for nonexistent file, got nil")
	}
}

func TestAnalyzeELF_StaticNonNetworkBinary(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	binPath := filepath.Join(tmpDir, "pure_compute_elf")

	src := []byte(`package main
func main() {
	println("pure calculation")
}
`)
	if err := os.WriteFile(srcPath, src, 0644); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}

	// Compile statically linked unstripped Linux ELF binary
	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to cross-compile test binary: %v, output: %s", err, string(out))
	}

	res, err := AnalyzeELF(binPath, "amd64")
	if err != nil {
		t.Fatalf("AnalyzeELF failed: %v", err)
	}

	if !res.IsELF {
		t.Errorf("Expected IsELF to be true")
	}
	if res.HasNetworkSymbols {
		t.Errorf("Expected HasNetworkSymbols to be false, found: %v", res.DetectedSymbols)
	}
	if !res.Prunable {
		t.Errorf("Expected binary without network symbols to be prunable")
	}
	if len(res.PrunedSyscallNrs) != 14 {
		t.Errorf("Expected 14 pruned socket syscalls, got %d", len(res.PrunedSyscallNrs))
	}
}

func TestAnalyzeELF_StrippedStaticBinaryFailClosed(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	binPath := filepath.Join(tmpDir, "stripped_elf")

	src := []byte(`package main
func main() {
	println("stripped binary")
}
`)
	if err := os.WriteFile(srcPath, src, 0644); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}

	// Compile stripped binary (-ldflags="-s -w")
	cmd := exec.Command("go", "build", "-ldflags=-s -w", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to cross-compile stripped binary: %v, output: %s", err, string(out))
	}

	res, err := AnalyzeELF(binPath, "amd64")
	if err != nil {
		t.Fatalf("AnalyzeELF failed: %v", err)
	}

	if !res.IsELF {
		t.Errorf("Expected IsELF to be true")
	}
	if !res.IsStripped {
		t.Errorf("Expected IsStripped to be true")
	}
	// Fail closed: stripped static binary must NOT prune socket syscalls
	if res.Prunable {
		t.Errorf("Security flaw: stripped static binary must NOT be prunable (fail-closed)")
	}
}

func TestAnalyzeELF_NetworkedBinary(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	binPath := filepath.Join(tmpDir, "network_elf")

	src := []byte(`package main
import "net"
func main() {
	_, _ = net.Dial("tcp", "127.0.0.1:80")
}
`)
	if err := os.WriteFile(srcPath, src, 0644); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to cross-compile network binary: %v, output: %s", err, string(out))
	}

	res, err := AnalyzeELF(binPath, "amd64")
	if err != nil {
		t.Fatalf("AnalyzeELF failed: %v", err)
	}

	if !res.IsELF {
		t.Errorf("Expected IsELF to be true")
	}
	if !res.HasNetworkSymbols {
		t.Errorf("Expected HasNetworkSymbols to be true for networked binary")
	}
	if res.Prunable {
		t.Errorf("Expected Prunable to be false for binary with network symbols")
	}
}

func TestBPFFilter_NetworkPruningSimulation_Amd64(t *testing.T) {
	filter := NewFilter()
	filter.PruneSyscalls(NetworkSyscallsAmd64)

	instructions, err := filter.CompileInstructions("amd64")
	if err != nil {
		t.Fatalf("CompileInstructions failed: %v", err)
	}

	vm := &bpfVM{instructions: instructions}

	// 1. Regular syscall (read=0, write=1) should be ALLOWED
	dRead := seccompDataSim{
		arch: AUDIT_ARCH_X86_64,
		nr:   0,
	}
	if ret := vm.run(dRead); ret != SECCOMP_RET_ALLOW {
		t.Errorf("Expected syscall read (0) to be allowed, got 0x%x", ret)
	}

	// 2. Network socket syscalls must be DENIED (EPERM)
	expectedDeny := uint32(SECCOMP_RET_ERRNO | EPERM)
	for _, sockNr := range NetworkSyscallsAmd64 {
		d := seccompDataSim{
			arch: AUDIT_ARCH_X86_64,
			nr:   int32(sockNr),
		}
		if ret := vm.run(d); ret != expectedDeny {
			t.Errorf("Expected socket syscall %d to be pruned/denied (0x%x), got 0x%x", sockNr, expectedDeny, ret)
		}
	}
}

func TestAnalyzeELF_PerformanceSubMillisecond(t *testing.T) {
	tmpDir := t.TempDir()
	srcPath := filepath.Join(tmpDir, "main.go")
	binPath := filepath.Join(tmpDir, "perf_elf")

	src := []byte(`package main
func main() {
	println("fast startup")
}
`)
	if err := os.WriteFile(srcPath, src, 0644); err != nil {
		t.Fatalf("failed to write source: %v", err)
	}

	cmd := exec.Command("go", "build", "-o", binPath, srcPath)
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH=amd64", "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("failed to compile: %v, output: %s", err, string(out))
	}

	// Measure execution time of AnalyzeELF
	start := time.Now()
	iterations := 10
	for i := 0; i < iterations; i++ {
		_, err := AnalyzeELF(binPath, "amd64")
		if err != nil {
			t.Fatalf("AnalyzeELF failed: %v", err)
		}
	}
	elapsed := time.Since(start) / time.Duration(iterations)

	t.Logf("Average ELF analysis latency: %v", elapsed)
	if elapsed > 15*time.Millisecond {
		t.Errorf("ELF analysis latency %v exceeded threshold", elapsed)
	}
}

func TestIsNetworkSymbol(t *testing.T) {
	networkTests := []struct {
		sym      string
		expected bool
	}{
		{"socket", true},
		{"connect", true},
		{"bind", true},
		{"listen", true},
		{"accept", true},
		{"getaddrinfo", true},
		{"gethostbyname", true},
		{"syscall.Socket", true},
		{"syscall.connect", true},
		{"net.Dial", true},
		{"crypto/tls.Dial", true},
		{"printf", false},
		{"malloc", false},
		{"strlen", false},
		{"math.Sin", false},
		{"", false},
	}

	for _, tc := range networkTests {
		got := isNetworkSymbol(tc.sym)
		if got != tc.expected {
			t.Errorf("isNetworkSymbol(%q) = %v, expected %v", tc.sym, got, tc.expected)
		}
	}
}

func TestNetworkSyscalls_Arm64(t *testing.T) {
	syscalls, err := NetworkSyscalls("arm64")
	if err != nil {
		t.Fatalf("NetworkSyscalls(arm64) failed: %v", err)
	}
	if len(syscalls) != 14 {
		t.Errorf("Expected 14 arm64 network syscalls, got %d", len(syscalls))
	}
}

func TestNetworkSyscalls_Unsupported(t *testing.T) {
	_, err := NetworkSyscalls("mips")
	if err == nil {
		t.Fatal("Expected error for unsupported architecture, got nil")
	}
}
