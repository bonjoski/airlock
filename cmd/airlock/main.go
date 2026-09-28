// Command airlock is the entrypoint for the Airlock workstation sandbox.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/shim"
)

var (
	version   = "1.0.0"
	commit    = "unknown"
	buildTime = "unknown"
)

func main() {
	if len(os.Args) < 2 {
		printUsage()
		os.Exit(1)
	}

	firstArg := os.Args[1]

	switch firstArg {
	case "help", "-h", "--help":
		printUsage()
		os.Exit(0)
	case "version", "-v", "--version":
		if commit != "unknown" && commit != "" {
			fmt.Printf("Airlock version %s (%s, built %s)\n", version, commit, buildTime)
		} else {
			fmt.Printf("Airlock version %s\n", version)
		}
		os.Exit(0)
	case "shim":
		handleShim(os.Args[2:])
		os.Exit(0)
	case "run":
		handleRun(os.Args[2:])
	default:
		// Direct shorthand: airlock npm install, airlock pip install, etc.
		if strings.HasPrefix(firstArg, "-") {
			// User passed top-level flags, e.g. airlock --airgap npm install
			handleRun(os.Args[1:])
		} else {
			// Direct command without flags: airlock npm install
			handleRun(os.Args[1:])
		}
	}
}

func printUsage() {
	fmt.Println(`Airlock — Minimalist Workstation Sandbox for Untrusted Package Installs & Agentic Loops

Usage:
  airlock run [flags] -- <command> [args...]
  airlock <command> [args...]
  airlock shim install [--target <dir>]
  airlock shim uninstall [--target <dir>]
  airlock version

Flags:
  --airgap              Total offline isolation (denies all outbound network traffic)
  --net                 Permit direct external outbound networking (development mode)
  --allow-domain <dom>  Comma-separated list of additional permitted registry domains
  --keep-env <var>      Comma-separated list of environment variables to preserve
  --vet                 Enable Argus pre-execution static analysis inspection
  --vet-strict          Fail closed / block execution on High or Critical security findings
  --vetpkg <path>       Path to external vetpkg / argus binary analyzer
  --non-interactive     Headless non-interactive pipe execution (for autonomous agent loops)
  --workspace <path>    Override the detected workspace root directory
  --scratch-base <dir>  Base directory for ephemeral scratch space allocation`)
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("airlock run", flag.ContinueOnError)

	var (
		airgap         bool
		allowDirectNet bool
		allowDomains   string
		keepEnv        string
		vetEnabled     bool
		vetStrict      bool
		vetTool        string
		nonInteractive bool
		workspace      string
		scratchBase    string
	)

	fs.BoolVar(&airgap, "airgap", false, "Offline isolation")
	fs.BoolVar(&allowDirectNet, "net", false, "Permit direct external network")
	fs.StringVar(&allowDomains, "allow-domain", "", "Additional registry domains")
	fs.StringVar(&keepEnv, "keep-env", "", "Preserve environment variables")
	fs.BoolVar(&vetEnabled, "vet", false, "Enable Argus static analysis inspection")
	fs.BoolVar(&vetStrict, "vet-strict", false, "Fail closed on high/critical findings")
	fs.StringVar(&vetTool, "vetpkg", "", "Path to external vetpkg/argus analyzer")
	fs.BoolVar(&nonInteractive, "non-interactive", false, "Force headless non-interactive pipe")
	fs.StringVar(&workspace, "workspace", "", "Override workspace root")
	fs.StringVar(&scratchBase, "scratch-base", "", "Scratch directory base")

	// Split flags from command at "--" if present
	cmdIndex := -1
	for i, arg := range args {
		if arg == "--" {
			cmdIndex = i
			break
		}
	}

	var flagArgs []string
	var cmdArgs []string

	if cmdIndex != -1 {
		flagArgs = args[:cmdIndex]
		cmdArgs = args[cmdIndex+1:]
	} else {
		var nonFlagStart = -1
		for i, arg := range args {
			if !strings.HasPrefix(arg, "-") {
				nonFlagStart = i
				break
			}
		}
		if nonFlagStart != -1 {
			flagArgs = args[:nonFlagStart]
			cmdArgs = args[nonFlagStart:]
		} else {
			flagArgs = args
		}
	}

	_ = fs.Parse(flagArgs)

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "airlock: no command specified for execution")
		os.Exit(1)
	}

	var extraDomains []string
	if allowDomains != "" {
		for _, d := range strings.Split(allowDomains, ",") {
			if trimmed := strings.TrimSpace(d); trimmed != "" {
				extraDomains = append(extraDomains, trimmed)
			}
		}
	}

	var keptEnvVars []string
	if keepEnv != "" {
		for _, k := range strings.Split(keepEnv, ",") {
			if trimmed := strings.TrimSpace(k); trimmed != "" {
				keptEnvVars = append(keptEnvVars, trimmed)
			}
		}
	}

	// 3. Open structured audit logger (~/.airlock/audit.log)
	auditLogger, auditErr := audit.NewDefaultLogger()
	if auditErr != nil {
		// Non-fatal: warn but proceed without telemetry
		fmt.Fprintf(os.Stderr, "airlock: warning: failed to open audit log: %v\n", auditErr)
		auditLogger = nil
	}
	if auditLogger != nil {
		defer func() { _ = auditLogger.Close() }()
	}

	var effectiveLogger audit.Logger = &audit.NopLogger{}
	if auditLogger != nil {
		effectiveLogger = auditLogger
	}

	opts := sandbox.Options{
		WorkspaceRoot:  workspace,
		Airgap:         airgap,
		AllowDirectNet: allowDirectNet,
		AllowedDomains: extraDomains,
		KeepEnv:        keptEnvVars,
		NonInteractive: nonInteractive,
		ScratchBase:    scratchBase,
		AuditLogger:    effectiveLogger,
		VetEnabled:     vetEnabled,
		VetStrict:      vetStrict,
		VetTool:        vetTool,
		Stdout:         os.Stdout,
		Stderr:         os.Stderr,
		Stdin:          os.Stdin,
	}

	engine, err := sandbox.NewEngine(opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock: initialization error: %v\n", err)
		os.Exit(1)
	}

	ctx := context.Background()
	start := time.Now()
	exitCode, err := engine.Execute(ctx, cmdArgs)

	_ = effectiveLogger.LogExecution(audit.ExecutionRecord{
		Command:        cmdArgs[0],
		Args:           cmdArgs[1:],
		WorkspaceRoot:  workspace,
		Airgap:         airgap,
		AllowDirectNet: allowDirectNet,
		AllowedDomains: extraDomains,
		DurationMs:     time.Since(start).Milliseconds(),
		ExitCode:       exitCode,
		Error: func() string {
			if err != nil {
				return err.Error()
			}
			return ""
		}(),
	})

	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock: execution failed: %v\n", err)
		os.Exit(exitCode)
	}

	os.Exit(exitCode)
}

func handleShim(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: airlock shim [install|uninstall|list] [--target <dir>]")
		return
	}

	action := args[0]
	targetDir := ""

	for i := 1; i < len(args); i++ {
		if args[i] == "--target" && i+1 < len(args) {
			targetDir = args[i+1]
			i++
		}
	}

	mgr := shim.NewManager()

	if targetDir == "" {
		def, err := mgr.DefaultShimDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to get shim directory: %v\n", err)
			os.Exit(1)
		}
		targetDir = def
	}

	switch action {
	case "install":
		installed, err := mgr.Install(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to install shims: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Installed %d Airlock shims in: %s\n", len(installed), targetDir)
		fmt.Println("To activate shims, prepend this directory to your PATH:")
		fmt.Printf("  export PATH=\"%s:$PATH\"\n", targetDir)

	case "uninstall":
		if err := mgr.Uninstall(targetDir); err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to uninstall shims: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Uninstalled Airlock shims from: %s\n", targetDir)

	case "list":
		statuses, err := mgr.List(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to list shims: %v\n", err)
			os.Exit(1)
		}
		for _, s := range statuses {
			state := "[ ]"
			if s.Installed {
				state = "[✓]"
			}
			hostBin := s.TargetHostBinary
			if hostBin == "" {
				hostBin = "(not found on PATH)"
			}
			fmt.Printf("%s %-10s → %s\n", state, s.Tool, hostBin)
		}

	default:
		fmt.Printf("Unknown shim action: %s. Use 'install', 'uninstall', or 'list'.\n", action)
	}
}
