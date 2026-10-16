package pty

import (
	"os"
	"testing"
)

func TestCheckTIOCSTI_NonTerminalFile(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("TIOCSTI ioctl is a Unix-specific vector, skipped on Windows")
	}
	// On a regular temporary file (not a TTY), ioctl with TIOCSTI MUST fail with ENOTTY
	tmp, err := os.CreateTemp("", "tiocsti-test")
	if err != nil {
		t.Fatalf("failed to create temp file: %v", err)
	}
	defer os.Remove(tmp.Name())
	defer tmp.Close()

	err = CheckTIOCSTI(tmp)
	if err == nil {
		t.Fatal("expected TIOCSTI on regular file to return error, got nil")
	}
	t.Logf("PASS: Non-terminal file descriptor correctly rejected TIOCSTI ioctl: %v", err)
}

func TestCheckTIOCSTI_NilFile(t *testing.T) {
	if os.Getenv("OS") == "Windows_NT" || os.PathSeparator == '\\' {
		t.Skip("TIOCSTI ioctl is a Unix-specific vector, skipped on Windows")
	}
	err := CheckTIOCSTI(nil)
	if err == nil {
		t.Fatal("expected error on nil file, got nil")
	}
}
