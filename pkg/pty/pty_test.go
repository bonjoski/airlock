package pty

import (
	"os"
	"testing"
)

func TestPOSIXDetector_IsTerminal(t *testing.T) {
	detector := NewDetector()

	// Temporary file should not be a terminal
	tmpFile, err := os.CreateTemp("", "airlock-test-pty-*")
	if err != nil {
		t.Fatalf("Failed to create temp file: %v", err)
	}
	defer os.Remove(tmpFile.Name())
	defer tmpFile.Close()

	if detector.IsTerminal(tmpFile) {
		t.Errorf("Expected regular file to return false for IsTerminal")
	}

	// Nil file should return false
	if detector.IsTerminal(nil) {
		t.Errorf("Expected nil file to return false for IsTerminal")
	}

	// Pipe ends should return false
	r, w, err := os.Pipe()
	if err != nil {
		t.Fatalf("Failed to create pipe: %v", err)
	}
	defer r.Close()
	defer w.Close()

	if detector.IsTerminal(r) {
		t.Errorf("Expected pipe read end to return false for IsTerminal")
	}
	if detector.IsTerminal(w) {
		t.Errorf("Expected pipe write end to return false for IsTerminal")
	}
}
