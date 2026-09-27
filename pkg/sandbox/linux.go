package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/airlock/pkg/cache"
	"github.com/bonjoski/airlock/pkg/env"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/pty"
	"github.com/bonjoski/airlock/pkg/scratch"
	"github.com/bonjoski/airlock/pkg/seccomp"
	"github.com/bonjoski/airlock/pkg/vet"
)

var (
	// ErrUsernsDisabled indicates unprivileged user namespaces are restricted on the host (V-07).
	ErrUsernsDisabled = errors.New("unprivileged user namespaces are disabled on host")
	// ErrBwrapNotFound indicates bubblewrap executable was not located.
	ErrBwrapNotFound = errors.New("bubblewrap (bwrap) executable not found on PATH")
)

// LinuxEngine executes commands inside a hardened Bubblewrap container
// backed by unprivileged user namespaces and Seccomp-BPF syscall filters.
type LinuxEngine struct {
	opts      Options
	cacheMgr  cache.Manager
	seccomp   seccomp.Filter
	detector  pty.Detector
	bwrapPath string
}

// NewLinuxEngine creates a new Linux sandbox engine using Bubblewrap and user namespaces.
func NewLinuxEngine(opts Options) (*LinuxEngine, error) {
	bwrapPath, err := exec.LookPath("bwrap")
	if err != nil {
		return nil, fmt.Errorf("sandbox: %w: %w", ErrBwrapNotFound, err)
	}

	eng := &LinuxEngine{
		opts:      opts,
		cacheMgr:  cache.NewManager(),
		seccomp:   seccomp.NewFilter(),
		detector:  pty.NewDetector(),
		bwrapPath: bwrapPath,
	}

	// Verify fail-closed user namespace availability on Linux hosts (V-07)
	if runtime.GOOS == "linux" {
		if err := eng.CheckUserNamespaces(); err != nil {
			return nil, fmt.Errorf("sandbox: fail-closed security abort: %w", err)
		}
	}

	return eng, nil
}

// CheckUserNamespaces inspects host configuration to ensure unprivileged user namespaces
// and process isolation primitives are functional (V-07: prevents unconfined fallback).
func (l *LinuxEngine) CheckUserNamespaces() error {
	// 1. Inspect sysctl parameter if present
	cloneSetting := "/proc/sys/kernel/unprivileged_userns_clone"
	if data, err := os.ReadFile(cloneSetting); err == nil {
		val := strings.TrimSpace(string(data))
		if val == "0" {
			return fmt.Errorf("%w: %s is 0", ErrUsernsDisabled, cloneSetting)
		}
	}

	// 2. Perform a dry-run invocation of bwrap to verify capability
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()

	cmd := exec.CommandContext(ctx, l.bwrapPath,
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind", "/usr", "/usr",
		"--proc", "/proc",
		"--dev", "/dev",
		"--",
		"true",
	)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: dry-run user namespace test failed: %w", ErrUsernsDisabled, err)
	}

	return nil
}

// FindWorkspaceSecrets discovers sensitive credential files in the workspace root
// that must be masked from untrusted read operations (V-04).
func FindWorkspaceSecrets(workspaceRoot string) ([]string, error) {
	entries, err := os.ReadDir(workspaceRoot)
	if err != nil {
		return nil, fmt.Errorf("sandbox: failed to inspect workspace: %w", err)
	}

	var secrets []string
	for _, entry := range entries {
		name := entry.Name()

		isSecret := strings.HasPrefix(name, ".env") ||
			strings.HasSuffix(name, ".pem") ||
			strings.HasPrefix(name, "id_rsa") ||
			strings.HasPrefix(name, "id_ed25519") ||
			strings.HasPrefix(name, "id_ecdsa") ||
			strings.HasPrefix(name, "id_dsa") ||
			name == "secrets.json" ||
			name == "service-account.json"

		if isSecret {
			secrets = append(secrets, filepath.Join(workspaceRoot, name))
		}
	}

	return secrets, nil
}

// BuildBwrapArgs synthesizes the complete argument list for bubblewrap execution.
func (l *LinuxEngine) BuildBwrapArgs(sc scratch.Manager, seccompFile *os.File, userHome string) ([]string, error) {
	args := []string{
		// Process & Namespace Isolation (V-07, V-09)
		"--unshare-user",
		"--unshare-ipc",
		"--unshare-pid",
		"--unshare-uts",
	}

	// Mandatory Network Namespace Detachment (V-09: isolates abstract Unix sockets @X11, @dbus)
	if l.opts.Airgap || !l.opts.AllowDirectNet {
		args = append(args, "--unshare-net")
	}

	// System Toolchains & Runtimes (Read-Only)
	systemDirs := []string{"/usr", "/lib", "/lib64", "/bin", "/sbin", "/opt", "/etc"}
	for _, sysDir := range systemDirs {
		args = append(args, "--ro-bind-try", sysDir, sysDir)
	}

	// Virtual filesystems
	args = append(args,
		"--proc", "/proc",
		"--dev", "/dev",
	)

	// Ephemeral Scratch Space (V-11: 0700 private directories)
	args = append(args,
		"--bind", sc.TmpDir(), "/tmp",
		"--bind", sc.HomeDir(), sc.HomeDir(),
		"--bind", sc.CacheStagingDir(), sc.CacheStagingDir(),
		"--setenv", "HOME", sc.HomeDir(),
		"--setenv", "TMPDIR", "/tmp",
	)

	// Workspace Root Mount (Read-Write for builds and installs)
	args = append(args,
		"--bind", l.opts.WorkspaceRoot, l.opts.WorkspaceRoot,
		"--chdir", l.opts.WorkspaceRoot,
	)

	// Git Metadata Protection (V-03: Workspace Poisoning Prevention)
	gitDir := filepath.Join(l.opts.WorkspaceRoot, ".git")
	args = append(args, "--ro-bind-try", gitDir, gitDir)

	// Workspace Secret Masking (V-04: Read Denial via 0000 unreadable file or /dev/null)
	unreadableMask := filepath.Join(sc.Root(), ".airlock_secret_mask")
	if err := os.WriteFile(unreadableMask, []byte{}, 0000); err == nil {
		secrets, _ := FindWorkspaceSecrets(l.opts.WorkspaceRoot)
		for _, secretPath := range secrets {
			args = append(args, "--ro-bind", unreadableMask, secretPath)
		}
	}

	// Read-Only Host Package Caches (V-12: Prevents Cold Cache Penalty)
	if l.cacheMgr != nil && userHome != "" {
		cacheMounts := l.cacheMgr.GetHostCacheMounts(userHome)
		for _, m := range cacheMounts {
			args = append(args, "--ro-bind-try", m.HostPath, m.HostPath)
		}
	}

	// Seccomp-BPF Syscall Filter Attachment (Target 2 / V-05, V-09)
	// When passed via cmd.ExtraFiles[0], the child FD is always 3.
	if seccompFile != nil {
		args = append(args, "--seccomp", "3")
	}

	// Ensure child terminates when supervisor exits
	args = append(args, "--die-with-parent", "--")

	return args, nil
}

// Execute runs the target command within the Linux Bubblewrap sandbox.
func (l *LinuxEngine) Execute(ctx context.Context, cmdArgs []string) (int, error) {
	if len(cmdArgs) == 0 {
		return 1, errors.New("sandbox: no command specified for execution")
	}

	// 1. Recursive Sandbox Detection (V-14 / Phase 1)
	if os.Getenv("__AIRLOCK_ACTIVE") == "1" {
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		cmd.Dir = l.opts.WorkspaceRoot
		cmd.Stdin = l.resolveStdin()
		cmd.Stdout = l.resolveStdout()
		cmd.Stderr = l.resolveStderr()
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode(), nil
			}
			return 1, fmt.Errorf("sandbox: nested execution failed: %w", err)
		}
		return 0, nil
	}

	// 2. Pre-Execution Static Analysis (Argus / vetpkg)
	inspector := l.opts.Inspector
	if inspector == nil && l.opts.VetEnabled {
		inspector = vet.NewEngine(vet.Config{
			StrictMode:   l.opts.VetStrict,
			ExternalTool: l.opts.VetTool,
			Logger:       l.opts.AuditLogger,
		})
	}
	if inspector != nil {
		report, err := inspector.Inspect(ctx, cmdArgs, l.opts.WorkspaceRoot)
		if err == nil && report != nil {
			for _, f := range report.Findings {
				fmt.Fprintf(l.resolveStderr(), "airlock [argus]: [%s] %s: %s\n", f.Severity, f.RuleID, f.Description)
			}
			if report.BlockExecution {
				return 1, fmt.Errorf("sandbox: execution blocked by Argus static analysis policy (risk: %s)", report.MaxRisk)
			}
		}
	}

	// 3. Orphan Scavenger (V-11)
	_, _ = scratch.ScavengeOrphans(l.opts.ScratchBase, 24*time.Hour)

	// 4. Ephemeral Scratch Space Allocation (V-11: 0700 perm)
	sc, err := scratch.New(l.opts.ScratchBase)
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to provision ephemeral scratch directory: %w", err)
	}
	defer func() {
		_ = sc.Cleanup()
	}()

	// 4. Start Egress Proxy (unless in airgap mode or direct network mode)
	var prx proxy.Proxy
	if !l.opts.Airgap && !l.opts.AllowDirectNet {
		p, err := proxy.NewWithLogger(l.opts.AllowedDomains, l.opts.AuditLogger)
		if err != nil {
			return 1, fmt.Errorf("sandbox: failed to start egress proxy: %w", err)
		}
		prx = p
		defer func() {
			_ = prx.Close()
		}()
	}

	proxyURL := ""
	dnsAddr := ""
	if prx != nil {
		proxyURL = prx.URL()
		if dp := prx.DNSPort(); dp > 0 {
			dnsAddr = fmt.Sprintf("127.0.0.1:%d", dp)
		}
	}

	// 5. Generate Seccomp-BPF Filter File (Target 2)
	seccompFile, err := l.seccomp.CreateFilterFile(runtime.GOARCH)
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to generate seccomp filter: %w", err)
	}
	defer func() {
		_ = seccompFile.Close()
		if rmErr := os.Remove(seccompFile.Name()); rmErr != nil && !os.IsNotExist(rmErr) {
			// Non-fatal cleanup warning
		}
	}()

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to resolve user home directory: %w", err)
	}

	// 6. Build Bubblewrap Arguments
	bwrapArgs, err := l.BuildBwrapArgs(sc, seccompFile, homeDir)
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to synthesize bubblewrap args: %w", err)
	}
	fullArgs := append(bwrapArgs, cmdArgs...)

	// 7. Sanitize Environment (V-07)
	envConfig := env.Config{
		VirtualHome:        sc.HomeDir(),
		ScratchDir:         sc.TmpDir(),
		StagingCache:       sc.CacheStagingDir(),
		ProxyURL:           proxyURL,
		DNSResolverAddress: dnsAddr,
		KeepEnv:            l.opts.KeepEnv,
	}
	sanitizer := env.NewSanitizer(envConfig)
	sanitizedEnv := sanitizer.Sanitize(os.Environ())

	// 8. Assemble Command Execution via bwrap
	cmd := exec.CommandContext(ctx, l.bwrapPath, fullArgs...)
	cmd.Dir = l.opts.WorkspaceRoot
	cmd.Env = sanitizedEnv
	cmd.Stdout = l.resolveStdout()
	cmd.Stderr = l.resolveStderr()
	cmd.ExtraFiles = []*os.File{seccompFile} // Passed as child FD 3

	// 9. Non-Interactive Pipe Handling (V-14)
	isInteractive := l.detector.IsTerminal(os.Stdin) && !l.opts.NonInteractive
	if isInteractive {
		cmd.Stdin = l.resolveStdin()
	} else {
		cmd.Stdin = nil
	}

	// 10. Signal Forwarding
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM, syscall.SIGHUP)
	defer signal.Stop(sigChan)

	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("sandbox: failed to start sandboxed process: %w", err)
	}

	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	// 11. Wait for Termination and Forward Exit Code
	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return 1, fmt.Errorf("sandbox: process wait failed: %w", err)
		}
	}

	// 12. Post-Execution Cache Synchronization (V-12: Zero Cold-Start Performance)
	if exitCode == 0 {
		if syncErr := l.cacheMgr.SyncBack(sc.CacheStagingDir(), homeDir); syncErr != nil {
			// Non-fatal warning on cache sync failure
			fmt.Fprintf(l.resolveStderr(), "airlock: warning: failed to sync staging cache: %v\n", syncErr)
		}
	}

	return exitCode, nil
}

func (l *LinuxEngine) resolveStdout() io.Writer {
	if l.opts.Stdout != nil {
		return l.opts.Stdout
	}
	return os.Stdout
}

func (l *LinuxEngine) resolveStderr() io.Writer {
	if l.opts.Stderr != nil {
		return l.opts.Stderr
	}
	return os.Stderr
}

func (l *LinuxEngine) resolveStdin() io.Reader {
	if l.opts.Stdin != nil {
		return l.opts.Stdin
	}
	return os.Stdin
}
