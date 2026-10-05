//go:build windows

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
	"unsafe"

	"github.com/bonjoski/airlock/pkg/cache"
	"github.com/bonjoski/airlock/pkg/env"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/pty"
	"github.com/bonjoski/airlock/pkg/scratch"
	"github.com/bonjoski/airlock/pkg/vet"
)

var (
	kernel32                     = syscall.NewLazyDLL("kernel32.dll")
	procCreateJobObjectW         = kernel32.NewProc("CreateJobObjectW")
	procSetInformationJobObject  = kernel32.NewProc("SetInformationJobObject")
	procAssignProcessToJobObject = kernel32.NewProc("AssignProcessToJobObject")
	procCloseHandle              = kernel32.NewProc("CloseHandle")
	procOpenProcess              = kernel32.NewProc("OpenProcess")
)

const (
	jobObjectExtendedLimitInformationClass = 9
	jobObjectLimitKillOnJobClose           = 0x00002000
	jobObjectLimitDieOnUnhandledException  = 0x00000400
	jobObjectLimitActiveProcess            = 0x00000008

	processSetQuota  = 0x0100
	processTerminate = 0x0001
)

type ioCounters struct {
	ReadOperationCount  uint64
	WriteOperationCount uint64
	OtherOperationCount uint64
	ReadTransferCount   uint64
	WriteTransferCount  uint64
	OtherTransferCount  uint64
}

type jobObjectBasicLimitInformation struct {
	PerProcessUserTimeLimit int64
	PerJobUserTimeLimit     int64
	LimitFlags              uint32
	MinimumWorkingSetSize   uintptr
	MaximumWorkingSetSize   uintptr
	ActiveProcessLimit      uint32
	Affinity                uintptr
	PriorityClass           uint32
	SchedulingClass         uint32
}

type jobObjectExtendedLimitInformation struct {
	BasicLimitInformation jobObjectBasicLimitInformation
	IoInfo                ioCounters
	ProcessMemoryLimit    uintptr
	JobMemoryLimit        uintptr
	PeakProcessMemoryUsed uintptr
	PeakJobMemoryUsed     uintptr
}

// WindowsEngine executes commands under Windows Job Object process confinement.
type WindowsEngine struct {
	opts     Options
	cacheMgr cache.Manager
	detector pty.Detector
}

// NewWindowsEngine creates a new Windows sandbox engine using Job Objects and proxy isolation.
func NewWindowsEngine(opts Options) (*WindowsEngine, error) {
	return &WindowsEngine{
		opts:     opts,
		cacheMgr: cache.NewManager(),
		detector: pty.NewDetector(),
	}, nil
}

// Execute runs the target command within the hardened Windows sandbox boundary.
func (w *WindowsEngine) Execute(ctx context.Context, cmdArgs []string) (int, error) {
	if len(cmdArgs) == 0 {
		return 1, errors.New("sandbox: no command specified for execution")
	}

	// 1. Recursive Sandbox Detection (V-14 / Phase 1)
	if os.Getenv("__AIRLOCK_ACTIVE") == "1" {
		cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
		cmd.Dir = w.opts.WorkspaceRoot
		cmd.Stdin = w.resolveStdin()
		cmd.Stdout = w.resolveStdout()
		cmd.Stderr = w.resolveStderr()
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
	inspector := w.opts.Inspector
	if inspector == nil && w.opts.VetEnabled {
		inspector = vet.NewEngine(vet.Config{
			StrictMode:   w.opts.VetStrict,
			ExternalTool: w.opts.VetTool,
			IgnoredRules: w.opts.IgnoredVetRules,
			Logger:       w.opts.AuditLogger,
		})
	}
	if inspector != nil {
		report, err := inspector.Inspect(ctx, cmdArgs, w.opts.WorkspaceRoot)
		if err == nil && report != nil {
			for _, f := range report.Findings {
				fmt.Fprintf(w.resolveStderr(), "airlock [argus]: [%s] %s: %s\n", f.Severity, f.RuleID, f.Description)
			}
			if report.BlockExecution {
				return 1, fmt.Errorf("sandbox: execution blocked by Argus static analysis policy (risk: %s)", report.MaxRisk)
			}
		}
	}

	// 3. Orphan Scavenger (V-11)
	_, _ = scratch.ScavengeOrphans(w.opts.ScratchBase, 24*time.Hour)

	// 4. Ephemeral Scratch Space Allocation (V-11)
	sc, err := scratch.New(w.opts.ScratchBase)
	if err != nil {
		return 1, fmt.Errorf("sandbox: failed to provision ephemeral scratch directory: %w", err)
	}
	defer func() {
		_ = sc.Cleanup()
	}()

	// 5. Start Egress Proxy (unless in airgap mode or direct network mode)
	var prx proxy.Proxy
	if !w.opts.Airgap && !w.opts.AllowDirectNet {
		p, err := proxy.NewWithOptions(proxy.Options{
			AllowedDomains: w.opts.AllowedDomains,
			Logger:         w.opts.AuditLogger,
			PromptHandler:  w.opts.PromptHandler,
			ConfigPath:     w.opts.ConfigPath,
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
	} else if w.opts.Airgap {
		// In airgap mode, point proxies to unreachable blackhole loopback port
		proxyURL = "http://127.0.0.1:0"
	}

	// 6. Create and Configure Windows Job Object
	hJob, _, jobErr := procCreateJobObjectW.Call(0, 0)
	if hJob == 0 {
		return 1, fmt.Errorf("sandbox: failed to create Windows Job Object: %v", jobErr)
	}
	defer procCloseHandle.Call(hJob)

	var info jobObjectExtendedLimitInformation
	info.BasicLimitInformation.LimitFlags = jobObjectLimitKillOnJobClose |
		jobObjectLimitDieOnUnhandledException |
		jobObjectLimitActiveProcess
	info.BasicLimitInformation.ActiveProcessLimit = 500 // Prevent fork-bomb resource exhaustion

	ret, _, setErr := procSetInformationJobObject.Call(
		hJob,
		uintptr(jobObjectExtendedLimitInformationClass),
		uintptr(unsafe.Pointer(&info)),
		uintptr(unsafe.Sizeof(info)),
	)
	if ret == 0 {
		return 1, fmt.Errorf("sandbox: failed to configure Job Object limits: %v", setErr)
	}

	// 7. Sanitize Environment (V-07)
	envConfig := env.Config{
		VirtualHome:        sc.HomeDir(),
		ScratchDir:         sc.TmpDir(),
		StagingCache:       sc.CacheStagingDir(),
		ProxyURL:           proxyURL,
		DNSResolverAddress: dnsAddr,
		KeepEnv:            w.opts.KeepEnv,
		DenyEnv:            w.opts.DenyEnv,
	}
	sanitizer := env.NewSanitizer(envConfig)
	sanitizedEnv := sanitizer.Sanitize(os.Environ())

	// 8. Assemble Command Execution
	cmd := exec.CommandContext(ctx, cmdArgs[0], cmdArgs[1:]...)
	cmd.Dir = w.opts.WorkspaceRoot
	cmd.Env = sanitizedEnv
	cmd.Stdout = w.resolveStdout()
	cmd.Stderr = w.resolveStderr()

	// 9. Non-Interactive Pipe Handling (V-14)
	isInteractive := w.detector.IsTerminal(os.Stdin) && !w.opts.NonInteractive
	if isInteractive {
		cmd.Stdin = w.resolveStdin()
	} else {
		cmd.Stdin = nil
	}

	// 10. Start Process
	if err := cmd.Start(); err != nil {
		return 1, fmt.Errorf("sandbox: failed to start sandboxed process: %w", err)
	}

	// 11. Assign Process to Job Object
	hProc, _, _ := procOpenProcess.Call(
		uintptr(processSetQuota|processTerminate),
		0,
		uintptr(cmd.Process.Pid),
	)
	if hProc != 0 {
		procAssignProcessToJobObject.Call(hJob, hProc)
		procCloseHandle.Call(hProc)
	}

	// 12. Signal Handling (Graceful termination forward)
	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt)
	defer signal.Stop(sigChan)

	go func() {
		for sig := range sigChan {
			if cmd.Process != nil {
				_ = cmd.Process.Signal(sig)
			}
		}
	}()

	// 13. Wait for Process Termination
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

	// 14. Post-Execution Cache Synchronization (V-12)
	homeDir, _ := os.UserHomeDir()
	if exitCode == 0 && homeDir != "" {
		if syncErr := w.cacheMgr.SyncBack(sc.CacheStagingDir(), homeDir); syncErr != nil {
			fmt.Fprintf(w.resolveStderr(), "airlock: warning: failed to sync staging cache: %v\n", syncErr)
		}
	}

	return exitCode, nil
}

func (w *WindowsEngine) resolveStdout() io.Writer {
	if w.opts.Stdout != nil {
		return w.opts.Stdout
	}
	return os.Stdout
}

func (w *WindowsEngine) resolveStderr() io.Writer {
	if w.opts.Stderr != nil {
		return w.opts.Stderr
	}
	return os.Stderr
}

func (w *WindowsEngine) resolveStdin() io.Reader {
	if w.opts.Stdin != nil {
		return w.opts.Stdin
	}
	return os.Stdin
}
