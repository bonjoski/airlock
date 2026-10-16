package protocol

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"os"
)

// HashFile returns the SHA-256 hash of an executable binary at path.
func HashFile(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", fmt.Errorf("peer: failed to open binary %q: %w", path, err)
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", fmt.Errorf("peer: failed to read binary %q: %w", path, err)
	}
	return "sha256:" + hex.EncodeToString(h.Sum(nil)), nil
}

// ClientIdentity provides verified identity markers for the current Airlock process.
type ClientIdentity struct {
	PID       int
	StartTime int64
	ExePath   string
	ExeHash   string
}

// GetCurrentClientIdentity captures the calling process's identity tuple.
func GetCurrentClientIdentity() (*ClientIdentity, error) {
	pid := os.Getpid()
	startTime, err := GetProcessStartTime(pid)
	if err != nil {
		return nil, err
	}

	exePath, err := os.Executable()
	if err != nil {
		return nil, fmt.Errorf("peer: failed to get current executable: %w", err)
	}

	var exeHash string
	if exePath != "" {
		h, err := HashFile(exePath)
		if err == nil {
			exeHash = h
		}
	}

	return &ClientIdentity{
		PID:       pid,
		StartTime: startTime,
		ExePath:   exePath,
		ExeHash:   exeHash,
	}, nil
}
