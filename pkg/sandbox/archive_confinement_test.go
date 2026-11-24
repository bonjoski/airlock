package sandbox

import (
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestValidateArchiveEntryPath_Benign(t *testing.T) {
	root := t.TempDir()
	cases := []string{
		"file.txt",
		"sub/dir/artifact.bin",
		"./nested/ok.json",
		"a/b/../c/file.go",
	}
	for _, entry := range cases {
		// Note: lexical ".." is strictly blocked even if it resolves inside root (fail-closed)
		if entry == "a/b/../c/file.go" {
			if _, err := ValidateArchiveEntryPath(root, entry); !errors.Is(err, ErrArchivePathEscape) {
				t.Errorf("expected parent traversal %q to be blocked fail-closed, got err=%v", entry, err)
			}
			continue
		}
		got, err := ValidateArchiveEntryPath(root, entry)
		if err != nil {
			t.Errorf("expected benign entry %q to pass, got error: %v", entry, err)
		}
		if got == "" {
			t.Errorf("expected non-empty resolved path for %q", entry)
		}
	}
}

func TestAdversarial_ArchiveEntryZipSlip(t *testing.T) {
	root := t.TempDir()
	outside := t.TempDir()

	// Create a symlink inside root pointing outside to test symlink-hop Zip-Slip escape
	if runtime.GOOS != "windows" {
		escapeLink := filepath.Join(root, "escape_link")
		if err := os.Symlink(outside, escapeLink); err != nil {
			t.Fatalf("failed to create escape symlink: %v", err)
		}
	}

	vectors := []struct {
		name  string
		entry string
	}{
		{"ClassicDotDot", "../../etc/passwd"},
		{"SingleDotDot", "../outside.txt"},
		{"WindowsBackslash", `..\..\Windows\System32\evil.dll`},
		{"MixedSeparators", `foo/..\..\escape.sh`},
		{"AbsolutePosix", "/etc/cron.d/backdoor"},
		{"AbsoluteUNC", `\\attacker\share\payload.exe`},
		{"WindowsDrive", `C:\Users\victim\.ssh\authorized_keys`},
		{"NullByte", "safe.txt\x00../../evil"},
		{"EncodedDotDot", "%2e%2e/outside.txt"},
		{"EmptyEntry", ""},
	}

	if runtime.GOOS != "windows" {
		vectors = append(vectors, struct {
			name  string
			entry string
		}{"SymlinkHopEscape", "escape_link/pwned.txt"})
	}

	for _, tc := range vectors {
		t.Run(tc.name, func(t *testing.T) {
			resolved, err := ValidateArchiveEntryPath(root, tc.entry)
			if !errors.Is(err, ErrArchivePathEscape) {
				t.Fatalf("FAIL-OPEN (GHSA-qh76-45cr-8xrc): entry %q was not blocked (resolved=%q, err=%v)", tc.entry, resolved, err)
			}
		})
	}
}

func TestAdversarial_ArchiveCommandConfinement(t *testing.T) {
	workspace := t.TempDir()
	outside := t.TempDir()

	if runtime.GOOS != "windows" {
		if err := os.Symlink(outside, filepath.Join(workspace, "out_link")); err != nil {
			t.Fatalf("failed to create symlink: %v", err)
		}
	}

	blocked := []struct {
		name string
		cmd  []string
	}{
		{"SevenZTraversalFlag", []string{"7z", "x", "payload.7z", "-o../../outside"}},
		{"SevenZAbsoluteOut", []string{"/usr/bin/7zz", "x", "payload.7z", "-o" + outside}},
		{"TarAbsoluteNamesShort", []string{"tar", "-P", "-xf", "archive.tar"}},
		{"TarAbsoluteNamesLong", []string{"TAR", "--absolute-names", "-xf", "archive.tar"}},
		{"TarKeepDirSymlink", []string{"bsdtar", "--keep-directory-symlink", "-xf", "archive.tar"}},
		{"TarOutsideDirC", []string{"tar", "-xf", "archive.tar", "-C", outside}},
		{"EnvWrappedTarOutside", []string{"env", "FOO=1", "tar", "-xf", "archive.tar", "--directory=" + outside}},
		{"UnzipOutsideD", []string{"unzip", "evil.zip", "-d", outside}},
		{"UnzipTraversalArg", []string{"unzip", "../../evil.zip"}},
		{"SevenZSymlinkFlag", []string{"7za", "x", "-snl", "evil.7z"}},
	}

	if runtime.GOOS != "windows" {
		blocked = append(blocked, struct {
			name string
			cmd  []string
		}{"SymlinkEscapeDest", []string{"tar", "-xf", "archive.tar", "-C", "out_link"}})
	}

	for _, tc := range blocked {
		t.Run("Block_"+tc.name, func(t *testing.T) {
			err := ValidateArchiveCommandConfinement(workspace, workspace, tc.cmd)
			if !errors.Is(err, ErrArchivePathEscape) {
				t.Fatalf("FAIL-OPEN: command %v should have been blocked by archive confinement, got err=%v", tc.cmd, err)
			}
		})
	}

	allowed := [][]string{
		{"tar", "-tzf", "release.tar.gz"},
		{"tar", "-xzf", "release.tar.gz", "-C", "build/out"},
		{"7z", "x", "archive.7z", "-odist/unpack"},
		{"unzip", "-d", "./tmp_extract", "artifact.zip"},
		{"git", "status"},
		{"go", "test", "./..."},
	}

	for _, cmd := range allowed {
		if err := ValidateArchiveCommandConfinement(workspace, workspace, cmd); err != nil {
			t.Errorf("FALSE POSITIVE: benign command %v was blocked: %v", cmd, err)
		}
	}
}
