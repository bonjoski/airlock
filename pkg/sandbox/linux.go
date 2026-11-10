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
	"github.com/bonjoski/airlock/pkg/secrets"
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
	opts                  Options
	cacheMgr              cache.Manager
	seccomp               seccomp.Filter
	detector              pty.Detector
	bwrapPath             string
	nestedVerifiedForTest bool
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

// SetOptionsForTest sets the engine options for unit testing purposes.
func (l *LinuxEngine) SetOptionsForTest(opts Options) {
	l.opts = opts
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

	dryRunArgs := []string{
		"--unshare-user",
		"--unshare-pid",
		"--ro-bind-try", "/usr", "/usr",
		"--ro-bind-try", "/lib", "/lib",
		"--ro-bind-try", "/lib64", "/lib64",
		"--ro-bind-try", "/bin", "/bin",
		"--ro-bind-try", "/etc", "/etc",
		"--proc", "/proc",
		"--dev", "/dev",
		"--",
		"true",
	}

	cmd := exec.CommandContext(ctx, l.bwrapPath, dryRunArgs...)
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%w: dry-run user namespace test failed: %w", ErrUsernsDisabled, err)
	}

	return nil
}

// FindWorkspaceSecrets discovers sensitive credential files across the workspace
// and its subdirectories that must be masked from untrusted read/write operations (V-04 / AIR-05).
func FindWorkspaceSecrets(workspaceRoot string) ([]string, error) {
	if _, err := os.Stat(workspaceRoot); err != nil {
		return nil, fmt.Errorf("sandbox: failed to inspect workspace: %w", err)
	}

	var found []string
	err := filepath.WalkDir(workspaceRoot, func(current string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			if current == workspaceRoot {
				return walkErr
			}
			return nil
		}
		if current == workspaceRoot {
			return nil
		}
		name := d.Name()
		if d.IsDir() {
			if name == ".git" {
				return filepath.SkipDir
			}
			return nil
		}
		// Only bind-mask regular files; symlinks are not followed
		if !d.Type().IsRegular() {
			return nil
		}

		isSecret := strings.HasPrefix(name, ".env") ||
			strings.HasSuffix(name, ".pem") ||
			strings.HasSuffix(name, ".key") ||
			strings.HasPrefix(name, "id_rsa") ||
			strings.HasPrefix(name, "id_ed25519") ||
			strings.HasPrefix(name, "id_ecdsa") ||
			strings.HasPrefix(name, "id_dsa") ||
			name == "secrets.json" ||
			name == "service-account.json"

		if isSecret {
			found = append(found, current)
		}
		return nil
	})
	if err != nil {
		return nil, fmt.Errorf("sandbox: failed to inspect workspace: %w", err)
	}

	return found, nil
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

	// Network Namespace Detachment (V-09 / AIR-06: Isolates network when airgapped or when direct network is disabled)
	isPermissive := strings.EqualFold(l.opts.Profile, "permissive")
	if l.opts.Airgap || strings.EqualFold(l.opts.Profile, "airgap") ||
		(!l.opts.AllowDirectNet && (l.opts.AntiLoopback || !isPermissive ||
			strings.EqualFold(l.opts.Profile, "anti-loopback") ||
			strings.EqualFold(l.opts.Profile, "anti_loopback") ||
			strings.EqualFold(l.opts.Profile, "agent") ||
			strings.EqualFold(l.opts.Profile, "dev-agent") ||
			strings.EqualFold(l.opts.Profile, "dev_agent") ||
			strings.EqualFold(l.opts.Profile, "strict-agent"))) {
		args = append(args, "--unshare-net")
	}

	// Whitelisted Unix Domain Sockets (CVE-2026-25253: explicit IPC whitelist)
	for _, sock := range l.opts.AllowedUnixSockets {
		if sock != "" {
			args = append(args, "--bind-try", sock, sock)
		}
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
		"--dir", sc.HomeDir(),
		"--bind", sc.HomeDir(), sc.HomeDir(),
		"--dir", sc.CacheStagingDir(),
		"--bind", sc.CacheStagingDir(), sc.CacheStagingDir(),
		"--setenv", "HOME", sc.HomeDir(),
		"--setenv", "TMPDIR", "/tmp",
	)

	chdirTarget := l.opts.WorkspaceRoot
	if l.opts.WorkingDir != "" {
		chdirTarget = l.opts.WorkingDir
	}

	// Workspace Root Mount (Read-Write for builds and installs)
	args = append(args,
		"--dir", l.opts.WorkspaceRoot,
		"--bind", l.opts.WorkspaceRoot, l.opts.WorkspaceRoot,
		"--chdir", chdirTarget,
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
			args = append(args, "--dir", m.HostPath, "--ro-bind-try", m.HostPath, m.HostPath)
		}
	}

	// Host user runtime toolchains for Go, Rust, Node, Python (Read-Only)
	if userHome != "" {
		userToolchains := []string{
			filepath.Join(userHome, ".cargo", "bin"),
			filepath.Join(userHome, ".rustup"),
			filepath.Join(userHome, "go", "bin"),
			filepath.Join(userHome, ".nvm"),
			filepath.Join(userHome, ".fnm"),
			filepath.Join(userHome, ".pyenv"),
			filepath.Join(userHome, ".local", "bin"),
		}
		for _, tc := range userToolchains {
			args = append(args, "--dir", tc, "--ro-bind-try", tc, tc)
		}
	}

	// Extra allowed read paths
	for _, p := range l.opts.ExtraAllowRead {
		cleaned := strings.TrimSpace(p)
		if cleaned == "" {
			continue
		}
		if strings.HasPrefix(cleaned, "~/") && userHome != "" {
			cleaned = filepath.Join(userHome, cleaned[2:])
		} else if !filepath.IsAbs(cleaned) {
			cleaned = filepath.Join(l.opts.WorkspaceRoot, cleaned)
		}
		// Skip if already within workspace root (which is already mounted)
		rel, err := filepath.Rel(l.opts.WorkspaceRoot, cleaned)
		if err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
			continue
		}
		args = append(args, "--dir", cleaned, "--ro-bind-try", cleaned, cleaned)
	}

	// Extra allowed write paths
	for _, p := range l.opts.ExtraAllowWrite {
		cleaned := strings.TrimSpace(p)
		if cleaned == "" {
			continue
		}
		if strings.HasPrefix(cleaned, "~/") && userHome != "" {
			cleaned = filepath.Join(userHome, cleaned[2:])
		} else if !filepath.IsAbs(cleaned) {
			cleaned = filepath.Join(l.opts.WorkspaceRoot, cleaned)
		}
		// Skip if already within workspace root (which is already mounted read-write)
		rel, err := filepath.Rel(l.opts.WorkspaceRoot, cleaned)
		if err == nil && !strings.HasPrefix(rel, "..") && rel != ".." {
			continue
		}
		args = append(args, "--dir", cleaned, "--bind-try", cleaned, cleaned)
	}

	// Seccomp-BPF Syscall Filter Attachment (Target 2 / V-05, V-09)
	// When passed via cmd.ExtraFiles[0], the child FD is always 3.
	if seccompFile != nil {
		args = append(args, "--seccomp", "3")
	}

	// Host credential masking across all profiles (AIR-05)
	if userHome != "" {
		hostSecretPaths := []string{
			filepath.Join(userHome, ".ssh"),
			filepath.Join(userHome, ".aws"),
			filepath.Join(userHome, ".gnupg"),
			filepath.Join(userHome, ".kube"),
			filepath.Join(userHome, ".docker"),
			filepath.Join(userHome, ".fabrial"),
			filepath.Join(userHome, ".npmrc"),
			filepath.Join(userHome, ".pypirc"),
			filepath.Join(userHome, ".netrc"),
			filepath.Join(userHome, ".config", "gh"),
			filepath.Join(userHome, ".config", "gcloud"),
		}
		for _, target := range hostSecretPaths {
			args = append(args, "--ro-bind-try", unreadableMask, target)
		}
	}

	// dev-agent profile extra hardening: capability dropping and /proc masking
	if strings.EqualFold(l.opts.Profile, "dev-agent") || strings.EqualFold(l.opts.Profile, "dev_agent") {
		args = append(args,
			"--cap-drop", "ALL",
			"--ro-bind-try", unreadableMask, "/proc/sys",
			"--ro-bind-try", unreadableMask, "/proc/kcore",
		)
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

	// 1. Pre-Execution Static Analysis (Argus / vetpkg) — ALWAYS enforced, even when nested (AIR-03)
	inspector := l.opts.Inspector
	if inspector == nil && l.opts.VetEnabled {
		inspector = vet.NewEngine(vet.Config{
			StrictMode:   l.opts.VetStrict,
			ExternalTool: l.opts.VetTool,
			IgnoredRules: l.opts.IgnoredVetRules,
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

	// 2. Kernel-Verified Recursive Sandbox Detection (V-14 / AIR-03)
	// Never trust caller-supplied __AIRLOCK_ACTIVE=1 unless PR_GET_SECCOMP confirms active confinement.
	if os.Getenv("__AIRLOCK_ACTIVE") == "1" {
		if isKernelSandboxed() || l.nestedVerifiedForTest {
			if l.opts.Airgap || strings.EqualFold(l.opts.Profile, "airgap") {
				return 1, errors.New("sandbox: cannot enforce --airgap inside an already-active nested sandbox session")
			}
			nestedEnv := env.BuildCleanEnvironment(env.Config{
				VirtualHome:        os.Getenv("HOME"),
				ScratchDir:         os.Getenv("TMPDIR"),
				ProxyURL:           os.Getenv("HTTP_PROXY"),
				DNSResolverAddress: os.Getenv("AIRLOCK_DNS"),
				KeepEnv:            l.opts.KeepEnv,
				DenyEnv:            l.opts.DenyEnv,
			}, os.Environ())

			cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
			if l.opts.WorkingDir != "" {
				cmd.Dir = l.opts.WorkingDir
			} else {
				cmd.Dir = l.opts.WorkspaceRoot
			}
			cmd.Env = nestedEnv
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
		fmt.Fprintf(l.resolveStderr(), "airlock: warning: ignoring unverified __AIRLOCK_ACTIVE=1 in unconfined process\n")
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
		p, err := proxy.NewWithOptions(proxy.Options{
			AllowedDomains: l.opts.AllowedDomains,
			Logger:         l.opts.AuditLogger,
			PromptHandler:  l.opts.PromptHandler,
			ConfigPath:     l.opts.ConfigPath,
		})
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

	// 4b. Static ELF Pre-Pass: inspect binary symbols to prune unneeded network syscalls
	targetBin := cmdArgs[0]
	if resolvedPath, err := exec.LookPath(targetBin); err == nil {
		targetBin = resolvedPath
	}
	if elfRes, err := seccomp.AnalyzeELF(targetBin, runtime.GOARCH); err == nil && elfRes != nil && elfRes.Prunable {
		l.seccomp.PruneSyscalls(elfRes.PrunedSyscallNrs)
		if os.Getenv("AIRLOCK_DEBUG") == "1" || l.opts.Debug {
			fmt.Fprintf(l.resolveStderr(), "airlock: [ELF-Analyze] No network symbols found. Pruned %d socket syscalls from BPF filter.\n", len(elfRes.PrunedSyscallNrs))
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

	// 7. Sanitize Environment (V-07 / AIR-02: Wire DenyEnv matching macos.go)
	envConfig := env.Config{
		VirtualHome:        sc.HomeDir(),
		ScratchDir:         sc.TmpDir(),
		StagingCache:       sc.CacheStagingDir(),
		ProxyURL:           proxyURL,
		DNSResolverAddress: dnsAddr,
		KeepEnv:            l.opts.KeepEnv,
		DenyEnv:            l.opts.DenyEnv,
	}
	sanitizer := env.NewSanitizer(envConfig)
	sanitizedEnv := sanitizer.Sanitize(os.Environ())

	// 7b. Ephemeral Secret Leasing (ETX / Locksmith Integration)
	if len(l.opts.LeasedSecrets) > 0 {
		lsClient := secrets.NewLocksmithClient(l.opts.LocksmithSocket)
		for _, secretName := range l.opts.LeasedSecrets {
			resp, cleanup, leaseErr := lsClient.RequestLease(ctx, secretName, 5*time.Minute, l.opts.SessionTicket)
			if leaseErr != nil {
				return 1, fmt.Errorf("sandbox: failed to lease secret %q from Locksmith: %w", secretName, leaseErr)
			}
			defer cleanup()
			sanitizedEnv = append(sanitizedEnv, fmt.Sprintf("%s=%s", secretName, string(resp.SecretValue)))
		}
	}

	// 8. Assemble Command Execution via bwrap
	cmd := exec.CommandContext(ctx, l.bwrapPath, fullArgs...)
	if l.opts.WorkingDir != "" {
		cmd.Dir = l.opts.WorkingDir
	} else {
		cmd.Dir = l.opts.WorkspaceRoot
	}
	cmd.Env = sanitizedEnv
	cmd.Stdout = l.resolveStdout()
	cmd.Stderr = l.resolveStderr()
	cmd.ExtraFiles = []*os.File{seccompFile} // Passed as child FD 3

	// 9. Non-Interactive Pipe Handling (V-14)
	detector := l.detector
	if detector == nil {
		detector = pty.NewDetector()
	}
	isInteractive := detector.IsTerminal(os.Stdin) && !l.opts.NonInteractive
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
