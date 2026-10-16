package bridge

import (
	"context"
	"os"
	"path/filepath"
	"testing"

	"github.com/bonjoski/airlock/pkg/sandbox"
)

func TestDiscoverAegisbox_EnvOverride(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-aegisbox")
	if err := os.WriteFile(fakeBin, []byte("#!/bin/sh\necho fake\n"), 0755); err != nil {
		t.Fatalf("failed to create fake binary: %v", err)
	}

	orig := os.Getenv("AEGISBOX_PATH")
	defer os.Setenv("AEGISBOX_PATH", orig)

	os.Setenv("AEGISBOX_PATH", fakeBin)

	p, err := DiscoverAegisbox()
	if err != nil {
		t.Fatalf("expected discovery to succeed, got %v", err)
	}
	if p != fakeBin {
		t.Fatalf("expected %s, got %s", fakeBin, p)
	}
}

func TestExecuteMicroVM_FakeBinary(t *testing.T) {
	tmpDir := t.TempDir()
	fakeBin := filepath.Join(tmpDir, "fake-aegisbox-runner")
	// Script that outputs args to stdout
	script := "#!/bin/sh\nexit 0\n"
	if err := os.WriteFile(fakeBin, []byte(script), 0755); err != nil {
		t.Fatalf("failed to write fake runner: %v", err)
	}

	orig := os.Getenv("AEGISBOX_PATH")
	defer os.Setenv("AEGISBOX_PATH", orig)
	os.Setenv("AEGISBOX_PATH", fakeBin)

	opts := sandbox.Options{
		WorkspaceRoot:  tmpDir,
		Airgap:         true,
		NonInteractive: true,
		LeasedSecrets:  []string{"OPENAI_API_KEY"},
	}

	code, err := ExecuteMicroVM(context.Background(), opts, []string{"echo", "hello"})
	if err != nil {
		t.Fatalf("unexpected error from ExecuteMicroVM: %v", err)
	}
	if code != 0 {
		t.Fatalf("expected exit code 0, got %d", code)
	}
}
