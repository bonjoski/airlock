package sandbox

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
	"time"

	"github.com/bonjoski/airlock/pkg/cache"
	"github.com/bonjoski/airlock/pkg/env"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/pty"
	"github.com/bonjoski/airlock/pkg/scratch"
	"github.com/bonjoski/airlock/pkg/seatbelt"
	"github.com/bonjoski/airlock/pkg/vet"
)

// MacOSEngine executes commands under macOS Seatbelt process confinement.
type MacOSEngine struct {
	opts      Options
	cacheMgr  cache.Manager
	generator seatbelt.Generator
	detector  pty.Detector
}

// NewMacOSEngine creates a new macOS Seatbelt sandboxing engine.
func NewMacOSEngine(opts Options) (*MacOSEngine, error) {
	if _, err := exec.LookPath("sandbox-exec"); err != nil {
		return nil, fmt.Errorf("sandbox: required utility 'sandbox-exec' not found on PATH: %w", err)
	}
	return &MacOSEngine{
		opts:      opts,
		cacheMgr:  cache.NewManager(),
		generator: seatbelt.NewGenerator(),
		detector:  pty.NewDetector(),
	}, nil
}

// Execute runs the target command within the hardened sandbox boundary.
func (m *MacOSEngine) Execute(ctx context.Context, cmdArgs []string) (int, error) {
	if len(cmdArgs) == 0 {
		return 1, errors.New("sandbox: no command specified for execution")
	}

	// 1. Recursive Sandbox Detection (V-14 / Phase 1)
	// If already running inside an active Airlock boundary, avoid nested sandbox crashes.
	if os.Getenv("__AIRLOCK_ACTIVE") == "1" {
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		cmd.Dir = m.opts.WorkspaceRoot
		cmd.Stdin = m.resolveStdin()
		cmd.Stdout = m.resolveStdout()
		cmd.Stderr = m.resolveStderr()
		if err := cmd.Run(); err != nil {
			var exitErr *exec.ExitError
			if errors.As(err, &exitErr) {
				return exitErr.ExitCode(), nil
			}
			return 1, err
		}
		return 0, nil
	}

	// 2. Pre-Execution Static Analysis (Argus / vetpkg)
	inspector := m.opts.Inspector
	if inspector == nil && m.opts.VetEnabled {
		inspector = vet.NewEngine(vet.Config{
			StrictMode:   m.opts.VetStrict,
			ExternalTool: m.opts.VetTool,
			IgnoredRules: m.opts.IgnoredVetRules,
			Logger:       m.opts.AuditLogger,
		})
	}
	if inspector != nil {
		report, err := inspector.Inspect(ctx, cmdArgs, m.opts.WorkspaceRoot)
		if err == nil && report != nil {
			for _, f := range report.Findings {
				fmt.Fprintf(m.resolveStderr(), "airlock [argus]: [%s] %s: %s\n", f.Severity, f.RuleID, f.Description)
			}
			if report.BlockExecution {
				return 1, fmt.Errorf("sandbox: execution blocked by Argus static analysis policy (risk: %s)", report.MaxRisk)
			}
		}
	}

	// 3. Orphan Scavenger (V-11: Prevents disk space leaks from crashes or SIGKILL)
	_, _ = scratch.ScavengeOrphans(m.opts.ScratchBase, 24*time.Hour)

	// 4. Ephemeral Scratch Space Allocation (V-11: Cryptographic mkdtemp, 0700 perm)
	sc, err := scratch.New(m.opts.ScratchBase)
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to provision ephemeral scratch directory: %w", err)
	}
	defer func() {
		_ = sc.Cleanup()
	}()

	// 4. Start Egress Proxy (unless in airgap mode or direct network mode)
	var prx proxy.Proxy
	if !m.opts.Airgap && !m.opts.AllowDirectNet {
		p, err := proxy.NewWithOptions(proxy.Options{
			AllowedDomains: m.opts.AllowedDomains,
			Logger:         m.opts.AuditLogger,
			PromptHandler:  m.opts.PromptHandler,
			ConfigPath:     m.opts.ConfigPath,
		})
		if err != nil {
			return 1, fmt.Errorf("sandbox: failed to start egress proxy: %w", err)
		}
		prx = p
		defer func() {
			_ = prx.Close()
		}()
	}

	proxyPort := 0
	proxyURL := ""
	dnsAddr := ""
	if prx != nil {
		proxyPort = prx.Port()
		proxyURL = prx.URL()
		if dp := prx.DNSPort(); dp > 0 {
			dnsAddr = fmt.Sprintf("127.0.0.1:%d", dp)
		}
	}

	// 5. Generate Hardened Seatbelt Scheme Profile
	homeDir, err := os.UserHomeDir()
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to resolve user home directory: %w", err)
	}

	seatbeltParams := seatbelt.Params{
		UserHome:        homeDir,
		WorkspaceRoot:   m.opts.WorkspaceRoot,
		ScratchDir:      sc.Root(),
		Airgap:          m.opts.Airgap,
		ProxyPort:       proxyPort,
		AllowDirectNet:  m.opts.AllowDirectNet,
		ExtraAllowRead:  m.opts.ExtraAllowRead,
		ExtraAllowWrite: m.opts.ExtraAllowWrite,
		ExtraDenyRead:   m.opts.ExtraDenyRead,
		ExtraDenyWrite:  m.opts.ExtraDenyWrite,
	}

	profileStr, err := m.generator.Generate(seatbeltParams)
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to synthesize Seatbelt profile: %w", err)
	}

	// 6. Sanitize Environment (V-07: Strict POSIX allowlist, clean PATH, virtual paths)
	envConfig := env.Config{
		VirtualHome:        sc.HomeDir(),
		ScratchDir:         sc.TmpDir(),
		StagingCache:       sc.CacheStagingDir(),
		ProxyURL:           proxyURL,
		DNSResolverAddress: dnsAddr,
		KeepEnv:            m.opts.KeepEnv,
		DenyEnv:            m.opts.DenyEnv,
	}

	sanitizer := env.NewSanitizer(envConfig)
	sanitizedEnv := sanitizer.Sanitize(os.Environ())

	// 7. Assemble Command Execution via sandbox-exec
	execArgs := append([]string{"-p", profileStr}, cmdArgs...)
	cmd := exec.CommandContext(ctx, "sandbox-exec", execArgs...)
	cmd.Dir = m.opts.WorkspaceRoot
	cmd.Env = sanitizedEnv
	cmd.Stdout = m.resolveStdout()
	cmd.Stderr = m.resolveStderr()

	// 8. Non-Interactive Pipe Handling (V-14 / Phase 1: Prevent Agent Loops Hanging on Stdin)
	isInteractive := m.detector.IsTerminal(os.Stdin) && !m.opts.NonInteractive
	if isInteractive {
		cmd.Stdin = m.resolveStdin()
	} else {
		// Provide nil/EOF if not interactive to prevent agent loops hanging
		cmd.Stdin = nil
	}

	// 9. Signal Forwarding
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

	// 10. Wait for Termination and Forward Exit Code
	err = cmd.Wait()
	exitCode := 0
	if err != nil {
		var exitErr *exec.ExitError
		if errors.As(err, &exitErr) {
			exitCode = exitErr.ExitCode()
		} else {
			return 1, err
		}
	}

	// 11. Post-Execution Cache Synchronization (V-12: Zero Cold-Start Performance)
	if exitCode == 0 {
		if syncErr := m.cacheMgr.SyncBack(sc.CacheStagingDir(), homeDir); syncErr != nil {
			fmt.Fprintf(m.resolveStderr(), "airlock: warning: failed to sync staging cache: %v\n", syncErr)
		}
	}

	return exitCode, nil
}

func (m *MacOSEngine) resolveStdout() io.Writer {
	if m.opts.Stdout != nil {
		return m.opts.Stdout
	}
	return os.Stdout
}

func (m *MacOSEngine) resolveStderr() io.Writer {
	if m.opts.Stderr != nil {
		return m.opts.Stderr
	}
	return os.Stderr
}

func (m *MacOSEngine) resolveStdin() io.Reader {
	if m.opts.Stdin != nil {
		return m.opts.Stdin
	}
	return os.Stdin
}
