package profile

import (
	"strings"
	"testing"

	"github.com/bonjoski/airlock/pkg/seatbelt"
)

func TestBuildWebWorkerSeccomp(t *testing.T) {
	for _, arch := range []string{"amd64", "x86_64", "arm64", "aarch64"} {
		t.Run(arch, func(t *testing.T) {
			filter, err := BuildWebWorkerSeccomp(arch)
			if err != nil {
				t.Fatalf("BuildWebWorkerSeccomp failed for %s: %v", arch, err)
			}
			blocked := filter.BlockedSyscalls()
			if len(blocked) < 2 {
				t.Errorf("expected at least 2 blocked syscalls (execve, execveat), got %d", len(blocked))
			}
		})
	}

	_, err := BuildWebWorkerSeccomp("mips")
	if err == nil {
		t.Error("expected error for unsupported architecture mips")
	}
}

func TestGenerateWebWorkerSeatbelt(t *testing.T) {
	p := seatbelt.Params{
		UserHome:      "/Users/webuser",
		WorkspaceRoot: "/var/www/html",
		ScratchDir:    "/tmp/scratch",
	}

	sb, err := GenerateWebWorkerSeatbelt(p)
	if err != nil {
		t.Fatalf("GenerateWebWorkerSeatbelt failed: %v", err)
	}

	for _, denied := range []string{"/bin/sh", "/bin/bash", "/bin/zsh"} {
		if !strings.Contains(sb, denied) {
			t.Errorf("Missing shell denial in web worker Seatbelt profile for %s", denied)
		}
	}
}

func TestAugmentBwrapArgsForWebWorker(t *testing.T) {
	baseArgs := []string{"bwrap"}
	augmented := AugmentBwrapArgsForWebWorker(baseArgs, "/var/www/html", "/tmp/worker_scratch")

	hasRoBind := false
	hasTmpfs := false
	hasCapDrop := false

	for i, a := range augmented {
		if a == "--ro-bind" && i+1 < len(augmented) && augmented[i+1] == "/var/www/html" {
			hasRoBind = true
		}
		if a == "--tmpfs" && i+1 < len(augmented) && augmented[i+1] == "/tmp/worker_scratch" {
			hasTmpfs = true
		}
		if a == "--cap-drop" && i+1 < len(augmented) && augmented[i+1] == "ALL" {
			hasCapDrop = true
		}
	}

	if !hasRoBind {
		t.Error("Missing --ro-bind /var/www/html")
	}
	if !hasTmpfs {
		t.Error("Missing --tmpfs /tmp/worker_scratch")
	}
	if !hasCapDrop {
		t.Error("Missing --cap-drop ALL")
	}
}
