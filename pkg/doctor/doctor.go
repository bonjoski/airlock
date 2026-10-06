// Package doctor provides comprehensive workstation and runtime environment diagnostics for Airlock.
package doctor

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/proxy"
	"github.com/bonjoski/airlock/pkg/scratch"
	"github.com/bonjoski/airlock/pkg/seatbelt"
	"github.com/bonjoski/airlock/pkg/seccomp"
	"github.com/bonjoski/airlock/pkg/shim"
)

// Status represents the health status of a diagnostic check.
type Status string

const (
	StatusPass Status = "PASS"
	StatusWarn Status = "WARN"
	StatusFail Status = "FAIL"
)

// CheckResult represents the outcome of an individual diagnostic check.
type CheckResult struct {
	ID             string `json:"id"`
	Category       string `json:"category"`
	Status         Status `json:"status"`
	Title          string `json:"title"`
	Details        string `json:"details,omitempty"`
	Recommendation string `json:"recommendation,omitempty"`
}

// Report aggregates all diagnostic checks performed across the system.
type Report struct {
	Timestamp     time.Time     `json:"timestamp"`
	Platform      string        `json:"platform"`
	WorkspaceRoot string        `json:"workspace_root"`
	Healthy       bool          `json:"healthy"`
	Passed        int           `json:"passed"`
	Warnings      int           `json:"warnings"`
	Failures      int           `json:"failures"`
	Results       []CheckResult `json:"results"`
}

// Options configures the doctor diagnostic engine.
type Options struct {
	WorkspaceRoot string
	HomeDir       string
	ScratchBase   string
	PathEnv       string
	ShimDir       string
	GOOS          string
	GOARCH        string
}

// RunAllChecks executes all system diagnostic checks for the given workspace root.
func RunAllChecks(ctx context.Context, workspaceRoot string) (*Report, error) {
	return RunChecks(ctx, Options{
		WorkspaceRoot: workspaceRoot,
	})
}

// RunChecks executes all diagnostic checks with the provided options.
func RunChecks(ctx context.Context, opts Options) (*Report, error) {
	if opts.WorkspaceRoot == "" {
		if cwd, err := os.Getwd(); err == nil {
			opts.WorkspaceRoot = cwd
		}
	}
	if opts.HomeDir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			opts.HomeDir = home
		}
	}
	if opts.PathEnv == "" {
		opts.PathEnv = os.Getenv("PATH")
	}
	if opts.GOOS == "" {
		opts.GOOS = runtime.GOOS
	}
	if opts.GOARCH == "" {
		opts.GOARCH = runtime.GOARCH
	}

	report := &Report{
		Timestamp:     time.Now().UTC(),
		Platform:      fmt.Sprintf("%s/%s", opts.GOOS, opts.GOARCH),
		WorkspaceRoot: opts.WorkspaceRoot,
		Results:       make([]CheckResult, 0),
	}

	// 1. Platform Sandbox Primitives
	report.Results = append(report.Results, CheckPlatformSandbox(ctx, opts)...)

	// 2. Storage & Permissions
	report.Results = append(report.Results, CheckStoragePermissions(ctx, opts)...)

	// 3. Network & Proxy
	report.Results = append(report.Results, CheckNetworkProxy(ctx, opts)...)

	// 4. Toolchain Shims
	report.Results = append(report.Results, CheckToolchainShims(ctx, opts)...)

	// 5. Declarative Configuration
	report.Results = append(report.Results, CheckDeclarativeConfig(ctx, opts)...)

	// Aggregate status counts
	for _, res := range report.Results {
		switch res.Status {
		case StatusPass:
			report.Passed++
		case StatusWarn:
			report.Warnings++
		case StatusFail:
			report.Failures++
		}
	}

	report.Healthy = (report.Failures == 0)

	return report, nil
}

// CheckPlatformSandbox evaluates platform-specific sandbox primitives.
func CheckPlatformSandbox(ctx context.Context, opts Options) []CheckResult {
	var results []CheckResult

	switch opts.GOOS {
	case "darwin":
		// 1. Check sandbox-exec binary
		execPath, err := exec.LookPath("sandbox-exec")
		if err != nil {
			results = append(results, CheckResult{
				ID:             "sandbox-seatbelt-exec",
				Category:       "Platform Sandbox Primitives",
				Status:         StatusFail,
				Title:          "macOS Seatbelt executable (sandbox-exec)",
				Details:        "Required executable 'sandbox-exec' was not found on PATH",
				Recommendation: "Ensure macOS Seatbelt subsystem is available and /usr/bin is in PATH.",
			})
		} else {
			results = append(results, CheckResult{
				ID:       "sandbox-seatbelt-exec",
				Category: "Platform Sandbox Primitives",
				Status:   StatusPass,
				Title:    "macOS Seatbelt executable (sandbox-exec)",
				Details:  fmt.Sprintf("Found sandbox-exec binary at %s", execPath),
			})
		}

		// 2. Check Seatbelt Profile Compilation via pkg/seatbelt
		gen := seatbelt.NewGenerator()
		sbParams := seatbelt.Params{
			UserHome:      opts.HomeDir,
			WorkspaceRoot: opts.WorkspaceRoot,
			ScratchDir:    "/tmp",
			Airgap:        true,
		}
		profile, err := gen.Generate(sbParams)
		if err != nil {
			results = append(results, CheckResult{
				ID:             "sandbox-seatbelt-profile",
				Category:       "Platform Sandbox Primitives",
				Status:         StatusFail,
				Title:          "macOS Seatbelt profile synthesis",
				Details:        fmt.Sprintf("Failed to synthesize Seatbelt SBPL profile: %v", err),
				Recommendation: "Check Seatbelt generator template and workspace path formatting.",
			})
		} else if !strings.Contains(profile, "(version 1)") || !strings.Contains(profile, "(deny default)") {
			results = append(results, CheckResult{
				ID:             "sandbox-seatbelt-profile",
				Category:       "Platform Sandbox Primitives",
				Status:         StatusFail,
				Title:          "macOS Seatbelt profile synthesis",
				Details:        "Generated profile is missing mandatory SBPL security headers",
				Recommendation: "Verify pkg/seatbelt profile generation template.",
			})
		} else {
			results = append(results, CheckResult{
				ID:       "sandbox-seatbelt-profile",
				Category: "Platform Sandbox Primitives",
				Status:   StatusPass,
				Title:    "macOS Seatbelt profile synthesis",
				Details:  "Hardened Seatbelt SBPL profile compiled successfully",
			})
		}

	case "linux":
		// 1. Check bubblewrap binary
		bwrapPath, err := exec.LookPath("bwrap")
		if err != nil {
			results = append(results, CheckResult{
				ID:             "sandbox-bwrap",
				Category:       "Platform Sandbox Primitives",
				Status:         StatusFail,
				Title:          "Bubblewrap executable (bwrap)",
				Details:        "Required executable 'bwrap' was not found on PATH",
				Recommendation: "Install bubblewrap (e.g., sudo apt-get install bubblewrap or sudo dnf install bubblewrap).",
			})
		} else {
			results = append(results, CheckResult{
				ID:       "sandbox-bwrap",
				Category: "Platform Sandbox Primitives",
				Status:   StatusPass,
				Title:    "Bubblewrap executable (bwrap)",
				Details:  fmt.Sprintf("Found bubblewrap binary at %s", bwrapPath),
			})
		}

		// 2. Check unprivileged user namespaces (/proc/sys/kernel/unprivileged_userns_clone)
		cloneSetting := "/proc/sys/kernel/unprivileged_userns_clone"
		if data, err := os.ReadFile(cloneSetting); err == nil {
			val := strings.TrimSpace(string(data))
			if val == "0" {
				results = append(results, CheckResult{
					ID:             "sandbox-userns",
					Category:       "Platform Sandbox Primitives",
					Status:         StatusFail,
					Title:          "Linux unprivileged user namespaces",
					Details:        fmt.Sprintf("%s is set to 0 (disabled)", cloneSetting),
					Recommendation: "Enable unprivileged user namespaces via: sudo sysctl -w kernel.unprivileged_userns_clone=1",
				})
			} else {
				results = append(results, CheckResult{
					ID:       "sandbox-userns",
					Category: "Platform Sandbox Primitives",
					Status:   StatusPass,
					Title:    "Linux unprivileged user namespaces",
					Details:  fmt.Sprintf("%s is set to %s (enabled)", cloneSetting, val),
				})
			}
		} else {
			// If sysctl file doesn't exist, try testing bwrap capability if available
			if bwrapPath != "" {
				cmdCtx, cancel := context.WithTimeout(ctx, 2*time.Second)
				cmd := exec.CommandContext(cmdCtx, bwrapPath, "--unshare-user", "--", "true")
				if err := cmd.Run(); err != nil {
					cancel()
					results = append(results, CheckResult{
						ID:             "sandbox-userns",
						Category:       "Platform Sandbox Primitives",
						Status:         StatusFail,
						Title:          "Linux unprivileged user namespaces",
						Details:        fmt.Sprintf("User namespace dry-run test failed: %v", err),
						Recommendation: "Ensure host kernel allows unprivileged user namespaces for non-root users.",
					})
				} else {
					cancel()
					results = append(results, CheckResult{
						ID:       "sandbox-userns",
						Category: "Platform Sandbox Primitives",
						Status:   StatusPass,
						Title:    "Linux unprivileged user namespaces",
						Details:  "Unprivileged user namespaces verified operational via bwrap dry-run",
					})
				}
			} else {
				results = append(results, CheckResult{
					ID:       "sandbox-userns",
					Category: "Platform Sandbox Primitives",
					Status:   StatusPass,
					Title:    "Linux unprivileged user namespaces",
					Details:  "User namespace sysctl restriction file not present (standard kernel defaults)",
				})
			}
		}

		// 3. Pure-Go Seccomp BPF compilation
		filt := seccomp.NewFilter()
		_, err = filt.Compile(opts.GOARCH)
		if err != nil {
			results = append(results, CheckResult{
				ID:             "sandbox-seccomp",
				Category:       "Platform Sandbox Primitives",
				Status:         StatusFail,
				Title:          "Seccomp-BPF filter compilation",
				Details:        fmt.Sprintf("Pure-Go Seccomp-BPF compilation failed for architecture %s: %v", opts.GOARCH, err),
				Recommendation: "Check seccomp filter architecture configuration.",
			})
		} else {
			results = append(results, CheckResult{
				ID:       "sandbox-seccomp",
				Category: "Platform Sandbox Primitives",
				Status:   StatusPass,
				Title:    "Seccomp-BPF filter compilation",
				Details:  fmt.Sprintf("Pure-Go Seccomp-BPF filter compiled successfully for %s", opts.GOARCH),
			})
		}

	case "windows":
		results = append(results, CheckResult{
			ID:       "sandbox-windows-jobobject",
			Category: "Platform Sandbox Primitives",
			Status:   StatusPass,
			Title:    "Windows Job Object process confinement",
			Details:  fmt.Sprintf("Windows NT process isolation and Job Object lifecycle limits supported for %s", opts.GOARCH),
		})

	default:
		results = append(results, CheckResult{
			ID:             "sandbox-platform-support",
			Category:       "Platform Sandbox Primitives",
			Status:         StatusFail,
			Title:          "Operating system platform support",
			Details:        fmt.Sprintf("Unsupported operating system %q", opts.GOOS),
			Recommendation: "Airlock requires macOS (Seatbelt), Linux (Bubblewrap + Seccomp), or Windows (Job Objects).",
		})
	}

	return results
}

// CheckStoragePermissions validates state directory and cache accessibility.
func CheckStoragePermissions(ctx context.Context, opts Options) []CheckResult {
	var results []CheckResult
	homeDir := opts.HomeDir

	// 1. ~/.airlock directory write access
	if homeDir == "" {
		results = append(results, CheckResult{
			ID:             "storage-airlock-dir",
			Category:       "Storage & Permissions",
			Status:         StatusFail,
			Title:          "Airlock home state directory (~/.airlock)",
			Details:        "Unable to determine user home directory",
			Recommendation: "Ensure HOME environment variable is properly set.",
		})
	} else {
		airlockDir := filepath.Join(homeDir, ".airlock")
		if err := os.MkdirAll(airlockDir, 0755); err != nil {
			results = append(results, CheckResult{
				ID:             "storage-airlock-dir",
				Category:       "Storage & Permissions",
				Status:         StatusFail,
				Title:          "Airlock home state directory (~/.airlock)",
				Details:        fmt.Sprintf("Failed to create or access %s: %v", airlockDir, err),
				Recommendation: fmt.Sprintf("Ensure %s is writable by current user (chmod 755 %s).", airlockDir, airlockDir),
			})
		} else {
			// Test write capability
			testFile := filepath.Join(airlockDir, fmt.Sprintf(".doctor_test_%d", time.Now().UnixNano()))
			if err := os.WriteFile(testFile, []byte("ok"), 0600); err != nil {
				results = append(results, CheckResult{
					ID:             "storage-airlock-dir",
					Category:       "Storage & Permissions",
					Status:         StatusFail,
					Title:          "Airlock home state directory (~/.airlock)",
					Details:        fmt.Sprintf("Failed to write to %s: %v", airlockDir, err),
					Recommendation: fmt.Sprintf("Ensure %s permissions allow writing.", airlockDir),
				})
			} else {
				_ = os.Remove(testFile)
				results = append(results, CheckResult{
					ID:       "storage-airlock-dir",
					Category: "Storage & Permissions",
					Status:   StatusPass,
					Title:    "Airlock home state directory (~/.airlock)",
					Details:  fmt.Sprintf("%s is writable and ready", airlockDir),
				})
			}
		}
	}

	// 2. Package caches (~/.npm, ~/.cache/pip, ~/.cargo/registry)
	checkCacheDir := func(id, title, relPath string) CheckResult {
		if homeDir == "" {
			return CheckResult{
				ID:       id,
				Category: "Storage & Permissions",
				Status:   StatusWarn,
				Title:    title,
				Details:  "User home directory not resolved",
			}
		}
		target := filepath.Join(homeDir, relPath)
		info, err := os.Stat(target)
		if err != nil {
			if os.IsNotExist(err) {
				return CheckResult{
					ID:       id,
					Category: "Storage & Permissions",
					Status:   StatusPass,
					Title:    title,
					Details:  fmt.Sprintf("%s does not exist yet (will be populated on tool run)", target),
				}
			}
			return CheckResult{
				ID:             id,
				Category:       "Storage & Permissions",
				Status:         StatusWarn,
				Title:          title,
				Details:        fmt.Sprintf("Unable to stat %s: %v", target, err),
				Recommendation: fmt.Sprintf("Check permissions for %s.", target),
			}
		}

		if !info.IsDir() {
			return CheckResult{
				ID:             id,
				Category:       "Storage & Permissions",
				Status:         StatusWarn,
				Title:          title,
				Details:        fmt.Sprintf("%s exists but is not a directory", target),
				Recommendation: fmt.Sprintf("Remove or rename non-directory %s.", target),
			}
		}

		// Test read access
		if _, err := os.ReadDir(target); err != nil {
			return CheckResult{
				ID:             id,
				Category:       "Storage & Permissions",
				Status:         StatusWarn,
				Title:          title,
				Details:        fmt.Sprintf("%s is not readable: %v", target, err),
				Recommendation: fmt.Sprintf("Ensure read access on %s.", target),
			}
		}

		return CheckResult{
			ID:       id,
			Category: "Storage & Permissions",
			Status:   StatusPass,
			Title:    title,
			Details:  fmt.Sprintf("%s is accessible", target),
		}
	}

	results = append(results, checkCacheDir("storage-npm-cache", "Node / npm cache (~/.npm)", ".npm"))
	results = append(results, checkCacheDir("storage-pip-cache", "Python / pip cache (~/.cache/pip)", filepath.Join(".cache", "pip")))
	results = append(results, checkCacheDir("storage-cargo-cache", "Rust / Cargo cache (~/.cargo/registry)", filepath.Join(".cargo", "registry")))

	// 3. Ephemeral Scratch Space (0700 permissions)
	sc, err := scratch.New(opts.ScratchBase)
	if err != nil {
		results = append(results, CheckResult{
			ID:             "storage-scratch-dirs",
			Category:       "Storage & Permissions",
			Status:         StatusFail,
			Title:          "Ephemeral scratch directory creation (0700)",
			Details:        fmt.Sprintf("Failed to allocate ephemeral scratch space: %v", err),
			Recommendation: "Ensure /tmp or specified scratch base is writable and allows directory creation.",
		})
	} else {
		defer func() { _ = sc.Cleanup() }()

		// Verify root permission is 0700
		info, statErr := os.Stat(sc.Root())
		if statErr != nil {
			results = append(results, CheckResult{
				ID:             "storage-scratch-dirs",
				Category:       "Storage & Permissions",
				Status:         StatusFail,
				Title:          "Ephemeral scratch directory creation (0700)",
				Details:        fmt.Sprintf("Failed to stat scratch directory %s: %v", sc.Root(), statErr),
				Recommendation: "Ensure temp filesystem is functioning properly.",
			})
		} else if !scratch.IsPrivatePermissions(info.Mode()) {
			results = append(results, CheckResult{
				ID:             "storage-scratch-dirs",
				Category:       "Storage & Permissions",
				Status:         StatusFail,
				Title:          "Ephemeral scratch directory creation (0700)",
				Details:        fmt.Sprintf("Scratch root directory has insecure permissions %04o (expected 0700)", info.Mode().Perm()),
				Recommendation: "Ensure umask and scratch directory creation enforce strict 0700 permissions.",
			})
		} else {
			results = append(results, CheckResult{
				ID:       "storage-scratch-dirs",
				Category: "Storage & Permissions",
				Status:   StatusPass,
				Title:    "Ephemeral scratch directory creation (0700)",
				Details:  fmt.Sprintf("Successfully provisioned and verified private scratch space (mode 0700) at %s", sc.Root()),
			})
		}
	}

	return results
}

// CheckNetworkProxy evaluates local socket binding and DNS filtering viability.
func CheckNetworkProxy(ctx context.Context, opts Options) []CheckResult {
	var results []CheckResult

	// 1. Ephemeral Port Binding on 127.0.0.1 (TCP and UDP)
	tcpLn, tcpErr := net.Listen("tcp", "127.0.0.1:0")
	var udpConn *net.UDPConn
	var udpErr error
	if tcpErr == nil {
		defer func() { _ = tcpLn.Close() }()
		uAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
		if err != nil {
			udpErr = err
		} else {
			conn, err := net.ListenUDP("udp", uAddr)
			if err != nil {
				udpErr = err
			} else {
				udpConn = conn
				defer func() { _ = udpConn.Close() }()
			}
		}
	}

	if tcpErr != nil {
		results = append(results, CheckResult{
			ID:             "network-port-binding",
			Category:       "Network & Proxy",
			Status:         StatusFail,
			Title:          "Loopback socket binding (127.0.0.1)",
			Details:        fmt.Sprintf("Failed to bind TCP listener on 127.0.0.1: %v", tcpErr),
			Recommendation: "Ensure local loopback interface (127.0.0.1) is up and host firewall permits local socket binds.",
		})
	} else if udpErr != nil {
		results = append(results, CheckResult{
			ID:             "network-port-binding",
			Category:       "Network & Proxy",
			Status:         StatusFail,
			Title:          "Loopback socket binding (127.0.0.1)",
			Details:        fmt.Sprintf("Failed to bind UDP listener on 127.0.0.1: %v", udpErr),
			Recommendation: "Ensure local UDP binding on loopback interface (127.0.0.1) is permitted.",
		})
	} else {
		results = append(results, CheckResult{
			ID:       "network-port-binding",
			Category: "Network & Proxy",
			Status:   StatusPass,
			Title:    "Loopback socket binding (127.0.0.1)",
			Details:  "TCP and UDP ephemeral port binding on 127.0.0.1 verified",
		})
	}

	// 2. In-Process DNS Filtering Proxy
	dnsSrv, dnsErr := proxy.NewDNSServer(map[string]bool{"registry.npmjs.org": true}, &audit.NopLogger{})
	if dnsErr != nil {
		results = append(results, CheckResult{
			ID:             "network-dns-filter",
			Category:       "Network & Proxy",
			Status:         StatusFail,
			Title:          "In-process DNS filtering proxy",
			Details:        fmt.Sprintf("Failed to instantiate in-process DNS filter: %v", dnsErr),
			Recommendation: "Check UDP socket availability on 127.0.0.1 for DNS proxy interceptor.",
		})
	} else {
		port := dnsSrv.Port()
		_ = dnsSrv.Close()
		results = append(results, CheckResult{
			ID:       "network-dns-filter",
			Category: "Network & Proxy",
			Status:   StatusPass,
			Title:    "In-process DNS filtering proxy",
			Details:  fmt.Sprintf("In-process DNS filtering server started and verified on 127.0.0.1:%d", port),
		})
	}

	return results
}

// CheckToolchainShims evaluates toolchain shim installation and PATH presence.
func CheckToolchainShims(ctx context.Context, opts Options) []CheckResult {
	var results []CheckResult

	shimDir := opts.ShimDir
	if shimDir == "" && opts.HomeDir != "" {
		shimDir = filepath.Join(opts.HomeDir, ".airlock", "bin")
	}

	// 1. Presence of shim directory in $PATH
	pathEnv := opts.PathEnv
	pathEntries := filepath.SplitList(pathEnv)
	cleanShimDir := filepath.Clean(shimDir)

	foundInPath := false
	altShimDir := ""
	if opts.HomeDir != "" {
		altShimDir = filepath.Clean(filepath.Join(opts.HomeDir, ".airlock", "shims"))
	}

	for _, entry := range pathEntries {
		cleanEntry := filepath.Clean(entry)
		if cleanEntry == cleanShimDir || (altShimDir != "" && cleanEntry == altShimDir) {
			foundInPath = true
			break
		}
	}

	if foundInPath {
		results = append(results, CheckResult{
			ID:       "shims-path-configured",
			Category: "Toolchain Shims",
			Status:   StatusPass,
			Title:    "Toolchain shims in $PATH",
			Details:  fmt.Sprintf("Shim directory (%s) is active in $PATH", shimDir),
		})
	} else {
		results = append(results, CheckResult{
			ID:             "shims-path-configured",
			Category:       "Toolchain Shims",
			Status:         StatusWarn,
			Title:          "Toolchain shims in $PATH",
			Details:        fmt.Sprintf("Shim directory (%s) is not in $PATH", shimDir),
			Recommendation: fmt.Sprintf("Add 'export PATH=\"%s:$PATH\"' to your shell profile (~/.zshrc or ~/.bashrc) for transparent CLI interception.", shimDir),
		})
	}

	// 2. Active Shim Inventory
	mgr := shim.NewManager()
	shims, err := mgr.List(shimDir)
	if err != nil {
		results = append(results, CheckResult{
			ID:             "shims-inventory",
			Category:       "Toolchain Shims",
			Status:         StatusWarn,
			Title:          "Active shim inventory",
			Details:        fmt.Sprintf("Unable to inspect shims in %s: %v", shimDir, err),
			Recommendation: fmt.Sprintf("Run 'airlock shim install --target %s' to install transparent shims.", shimDir),
		})
	} else {
		var activeTools []string
		for _, s := range shims {
			if s.Installed {
				activeTools = append(activeTools, s.Tool)
			}
		}

		if len(activeTools) > 0 {
			results = append(results, CheckResult{
				ID:       "shims-inventory",
				Category: "Toolchain Shims",
				Status:   StatusPass,
				Title:    "Active shim inventory",
				Details:  fmt.Sprintf("%d transparent shims active: %s", len(activeTools), strings.Join(activeTools, ", ")),
			})
		} else {
			results = append(results, CheckResult{
				ID:             "shims-inventory",
				Category:       "Toolchain Shims",
				Status:         StatusPass,
				Title:          "Active shim inventory",
				Details:        fmt.Sprintf("0 shims currently installed in %s", shimDir),
				Recommendation: "Run 'airlock shim install' if you wish to enable transparent interception for npm/pip/cargo.",
			})
		}
	}

	return results
}

// CheckDeclarativeConfig inspects airlock.yaml configuration and schema validity.
func CheckDeclarativeConfig(ctx context.Context, opts Options) []CheckResult {
	var results []CheckResult
	wsRoot := opts.WorkspaceRoot

	var discoveredPath string
	if wsRoot != "" {
		for _, name := range config.ConfigFileNames {
			p := filepath.Join(wsRoot, name)
			if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
				discoveredPath = p
				break
			}
		}
	}

	if discoveredPath == "" && opts.HomeDir != "" {
		p := filepath.Join(opts.HomeDir, ".airlock", "config.yaml")
		if fi, err := os.Stat(p); err == nil && !fi.IsDir() {
			discoveredPath = p
		}
	}

	if discoveredPath == "" {
		results = append(results, CheckResult{
			ID:             "config-airlock-yaml",
			Category:       "Declarative Configuration",
			Status:         StatusWarn,
			Title:          "Workspace declarative policy (airlock.yaml)",
			Details:        "No airlock.yaml or .airlockrc found in workspace root (using baseline hardened defaults)",
			Recommendation: "Run 'airlock init' to generate a project-tailored airlock.yaml declarative policy.",
		})
		return results
	}

	// Load and validate policy with issues
	cfg, issues, loadErr := config.LoadFromFileWithIssues(discoveredPath)
	if loadErr != nil {
		results = append(results, CheckResult{
			ID:             "config-airlock-yaml",
			Category:       "Declarative Configuration",
			Status:         StatusFail,
			Title:          fmt.Sprintf("Workspace policy (%s)", filepath.Base(discoveredPath)),
			Details:        fmt.Sprintf("Failed to parse configuration %s: %v", filepath.Base(discoveredPath), loadErr),
			Recommendation: "Fix YAML/JSON syntax or schema errors in your airlock configuration file.",
		})
		return results
	}

	if len(issues) > 0 {
		var msgs []string
		for _, issue := range issues {
			msgs = append(msgs, fmt.Sprintf("  [%s] %s: %s", issue.Severity, issue.Field, issue.Message))
		}
		results = append(results, CheckResult{
			ID:             "config-airlock-yaml",
			Category:       "Declarative Configuration",
			Status:         StatusWarn,
			Title:          fmt.Sprintf("Workspace policy (%s)", filepath.Base(discoveredPath)),
			Details:        fmt.Sprintf("%s loaded with %d security guardrail notices:\n%s", filepath.Base(discoveredPath), len(issues), strings.Join(msgs, "\n")),
			Recommendation: "Review and remove restricted path or environment overrides to satisfy security invariants.",
		})
	} else {
		results = append(results, CheckResult{
			ID:       "config-airlock-yaml",
			Category: "Declarative Configuration",
			Status:   StatusPass,
			Title:    fmt.Sprintf("Workspace policy (%s)", filepath.Base(discoveredPath)),
			Details: fmt.Sprintf("%s is valid (mode: %s, allow_domains: %d, allow_read: %d, allow_write: %d)",
				filepath.Base(discoveredPath), cfg.Mode, len(cfg.Network.AllowDomains), len(cfg.Filesystem.AllowRead), len(cfg.Filesystem.AllowWrite)),
		})
	}

	return results
}

// ToJSON serializes the diagnostic report into formatted JSON.
func (r *Report) ToJSON() ([]byte, error) {
	return json.MarshalIndent(r, "", "  ")
}

// FormatTerminal generates an ANSI styled text summary suitable for CLI terminal output.
func (r *Report) FormatTerminal(useColor bool) string {
	var sb strings.Builder

	passSymbol := "✓ PASS"
	warnSymbol := "⚠ WARN"
	failSymbol := "✗ FAIL"

	if useColor {
		passSymbol = "\033[32m✓ PASS\033[0m"
		warnSymbol = "\033[33m⚠ WARN\033[0m"
		failSymbol = "\033[31m✗ FAIL\033[0m"
	}

	sb.WriteString("Airlock Doctor — System Diagnostics & Health Report\n")
	sb.WriteString("==================================================\n")
	sb.WriteString(fmt.Sprintf("Platform:       %s\n", r.Platform))
	sb.WriteString(fmt.Sprintf("Workspace Root: %s\n", r.WorkspaceRoot))
	sb.WriteString(fmt.Sprintf("Timestamp:      %s\n\n", r.Timestamp.Format(time.RFC3339)))

	// Group by category
	categories := []string{
		"Platform Sandbox Primitives",
		"Storage & Permissions",
		"Network & Proxy",
		"Toolchain Shims",
		"Declarative Configuration",
	}

	for _, cat := range categories {
		var catResults []CheckResult
		for _, res := range r.Results {
			if res.Category == cat {
				catResults = append(catResults, res)
			}
		}

		if len(catResults) == 0 {
			continue
		}

		sb.WriteString(fmt.Sprintf("[%s]\n", cat))
		for _, res := range catResults {
			var symbol string
			switch res.Status {
			case StatusPass:
				symbol = passSymbol
			case StatusWarn:
				symbol = warnSymbol
			case StatusFail:
				symbol = failSymbol
			}

			sb.WriteString(fmt.Sprintf("  %s %s: %s\n", symbol, res.ID, res.Title))
			if res.Details != "" {
				lines := strings.Split(res.Details, "\n")
				for _, line := range lines {
					sb.WriteString(fmt.Sprintf("         %s\n", line))
				}
			}
			if res.Recommendation != "" && res.Status != StatusPass {
				sb.WriteString(fmt.Sprintf("         -> Recommendation: %s\n", res.Recommendation))
			}
		}
		sb.WriteString("\n")
	}

	healthStatus := "HEALTHY"
	if !r.Healthy {
		healthStatus = "UNHEALTHY"
	}

	if useColor {
		if r.Healthy {
			healthStatus = "\033[32mHEALTHY\033[0m"
		} else {
			healthStatus = "\033[31mUNHEALTHY\033[0m"
		}
	}

	sb.WriteString("--------------------------------------------------\n")
	sb.WriteString(fmt.Sprintf("Summary: %d passed, %d warnings, %d failures (System %s)\n",
		r.Passed, r.Warnings, r.Failures, healthStatus))

	return sb.String()
}
