// Command airlock is the entrypoint for the Airlock workstation sandbox.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
	"github.com/bonjoski/airlock/pkg/config"
	"github.com/bonjoski/airlock/pkg/interactive"
	"github.com/bonjoski/airlock/pkg/mcp"
	"github.com/bonjoski/airlock/pkg/pty"
	"github.com/bonjoski/airlock/pkg/sandbox"
	"github.com/bonjoski/airlock/pkg/shim"
)

var (
	version   = "1.1.0"
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
	case "init":
		handleInit(os.Args[2:])
		os.Exit(0)
	case "config":
		handleConfig(os.Args[2:])
		os.Exit(0)
	case "shim":
		handleShim(os.Args[2:])
		os.Exit(0)
	case "doctor":
		handleDoctor(os.Args[2:])
		os.Exit(0)
	case "audit":
		handleAudit(os.Args[2:])
		os.Exit(0)
	case "mcp":
		handleMCP(os.Args[2:])
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
  airlock init [--type <node|python|rust|go>]
  airlock config validate [--config <path>]
  airlock shim install [--target <dir>]
  airlock shim uninstall [--target <dir>]
  airlock doctor [--json] [--workspace <path>]
  airlock audit [list|tail|stats|export] [flags]
  airlock mcp
  airlock version

Flags:
  --config <path>       Path to custom airlock.yaml declarative policy file
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

func handleInit(args []string) {
	fs := flag.NewFlagSet("airlock init", flag.ExitOnError)
	projectType := fs.String("type", "", "Project profile: node, python, rust, go, or general")
	force := fs.Bool("force", false, "Overwrite existing policy file if present")
	outPath := fs.String("output", "airlock.yaml", "Destination configuration file path")
	_ = fs.Parse(args)

	if _, err := os.Stat(*outPath); err == nil && !*force {
		fmt.Fprintf(os.Stderr, "airlock: %s already exists (use --force to overwrite)\n", *outPath)
		os.Exit(1)
	}

	typ := *projectType
	if typ == "" {
		typ = detectProjectType(".")
	}

	content := config.GenerateTemplate(typ)
	if err := os.WriteFile(*outPath, []byte(content), 0644); err != nil {
		fmt.Fprintf(os.Stderr, "airlock: failed to write %s: %v\n", *outPath, err)
		os.Exit(1)
	}

	fmt.Printf("Airlock: initialized %s declarative policy (%s profile)\n", *outPath, typ)
}

func handleConfig(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: airlock config validate [--config <path>]")
		os.Exit(1)
	}
	if args[0] == "validate" {
		fs := flag.NewFlagSet("airlock config validate", flag.ExitOnError)
		configPath := fs.String("config", "", "Path to configuration file")
		_ = fs.Parse(args[1:])

		path := *configPath
		var cfg *config.Config
		var issues []config.ValidationIssue
		var err error
		if path != "" {
			cfg, issues, err = config.LoadFromFileWithIssues(path)
		} else {
			path, _, _ = config.DiscoverConfig(".")
			if path != "" {
				cfg, issues, err = config.LoadFromFileWithIssues(path)
			}
		}

		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock config: invalid configuration: %v\n", err)
			os.Exit(1)
		}

		if cfg == nil {
			fmt.Println("airlock config: no airlock.yaml or .airlockrc found (using baseline hardened defaults)")
			os.Exit(0)
		}

		if len(issues) > 0 {
			fmt.Printf("airlock config: %s validated with security guardrail alerts:\n", path)
			for _, issue := range issues {
				fmt.Printf("  [%s] %s: %s\n", issue.Severity, issue.Field, issue.Message)
			}
		} else {
			fmt.Printf("airlock config: %s is valid (mode: %s, allow_domains: %d, allow_read: %d)\n",
				path, cfg.Mode, len(cfg.Network.AllowDomains), len(cfg.Filesystem.AllowRead))
		}
	} else {
		fmt.Printf("airlock config: unknown subcommand %q\n", args[0])
		os.Exit(1)
	}
}

func detectProjectType(dir string) string {
	if _, err := os.Stat(filepath.Join(dir, "package.json")); err == nil {
		return "node"
	}
	if _, err := os.Stat(filepath.Join(dir, "Cargo.toml")); err == nil {
		return "rust"
	}
	if _, err := os.Stat(filepath.Join(dir, "pyproject.toml")); err == nil {
		return "python"
	}
	if _, err := os.Stat(filepath.Join(dir, "requirements.txt")); err == nil {
		return "python"
	}
	if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
		return "go"
	}
	return "general"
}

func handleRun(args []string) {
	fs := flag.NewFlagSet("airlock run", flag.ContinueOnError)

	var (
		configPath     string
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

	fs.StringVar(&configPath, "config", "", "Path to declarative policy file")
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

	// 1. Resolve Workspace Root
	resolvedWorkspace := workspace
	if resolvedWorkspace == "" {
		cwd, err := os.Getwd()
		if err == nil {
			resolvedWorkspace = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	// 2. Discover & Load Declarative Policy (airlock.yaml)
	var loadedCfg *config.Config
	var discoveredConfigPath string
	if configPath != "" {
		cfg, err := config.LoadFromFile(configPath)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: error loading config %q: %v\n", configPath, err)
			os.Exit(1)
		}
		loadedCfg = cfg
		discoveredConfigPath = configPath
	} else {
		p, cfg, err := config.DiscoverConfig(resolvedWorkspace)
		if err == nil && cfg != nil {
			loadedCfg = cfg
			discoveredConfigPath = p
		}
	}

	var extraDomains []string
	var keptEnvVars []string
	var deniedEnvVars []string
	var extraAllowRead []string
	var extraAllowWrite []string
	var extraDenyRead []string
	var extraDenyWrite []string
	var ignoredVetRules []string
	promptTimeout := 15

	if loadedCfg != nil {
		config.SanitizeAndEnforceGuardrails(loadedCfg)

		if loadedCfg.Network.Airgap && !allowDirectNet {
			airgap = true
		}
		extraDomains = append(extraDomains, loadedCfg.Network.AllowDomains...)
		keptEnvVars = append(keptEnvVars, loadedCfg.Env.Allow...)
		deniedEnvVars = append(deniedEnvVars, loadedCfg.Env.Deny...)
		extraAllowRead = append(extraAllowRead, loadedCfg.Filesystem.AllowRead...)
		extraAllowWrite = append(extraAllowWrite, loadedCfg.Filesystem.AllowWrite...)
		extraDenyRead = append(extraDenyRead, loadedCfg.Filesystem.DenyRead...)
		extraDenyWrite = append(extraDenyWrite, loadedCfg.Filesystem.DenyWrite...)

		if loadedCfg.Vetting.Enable {
			vetEnabled = true
		}
		if loadedCfg.Vetting.Strict {
			vetStrict = true
		}
		ignoredVetRules = append(ignoredVetRules, loadedCfg.Vetting.IgnoredRules...)
		if loadedCfg.Interactive.PromptTimeoutSec > 0 {
			promptTimeout = loadedCfg.Interactive.PromptTimeoutSec
		}
	}

	if allowDomains != "" {
		for _, d := range strings.Split(allowDomains, ",") {
			if trimmed := strings.TrimSpace(d); trimmed != "" {
				extraDomains = append(extraDomains, trimmed)
			}
		}
	}

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

	// 4. Configure Dynamic Capability Prompter for interactive sessions
	detector := pty.NewDetector()
	isTTY := detector.IsTerminal(os.Stdin) && !nonInteractive
	var promptHandler func(domain string) interactive.Grant

	if isTTY && (loadedCfg == nil || loadedCfg.Interactive.PromptOnUnknownDomain) {
		prompter := interactive.NewTerminalPrompter(discoveredConfigPath, time.Duration(promptTimeout)*time.Second)
		promptHandler = prompter.PromptDomain
	}

	opts := sandbox.Options{
		WorkspaceRoot:   resolvedWorkspace,
		ConfigPath:      discoveredConfigPath,
		Airgap:          airgap,
		AllowDirectNet:  allowDirectNet,
		AllowedDomains:  extraDomains,
		KeepEnv:         keptEnvVars,
		DenyEnv:         deniedEnvVars,
		ExtraAllowRead:  extraAllowRead,
		ExtraAllowWrite: extraAllowWrite,
		ExtraDenyRead:   extraDenyRead,
		ExtraDenyWrite:  extraDenyWrite,
		NonInteractive:  nonInteractive,
		ScratchBase:     scratchBase,
		AuditLogger:     effectiveLogger,
		VetEnabled:      vetEnabled,
		VetStrict:       vetStrict,
		VetTool:         vetTool,
		IgnoredVetRules: ignoredVetRules,
		PromptHandler:   promptHandler,
		Stdout:          os.Stdout,
		Stderr:          os.Stderr,
		Stdin:           os.Stdin,
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
		WorkspaceRoot:  resolvedWorkspace,
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
	effectiveDir := targetDir
	if effectiveDir == "" {
		if def, err := mgr.DefaultShimDir(); err == nil {
			effectiveDir = def
		}
	}

	switch action {
	case "install":
		installed, err := mgr.Install(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to install shims: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Airlock: successfully installed %d transparent shims in %s\n", len(installed), effectiveDir)
		for _, tool := range installed {
			fmt.Printf("  -> %s\n", tool)
		}
		fmt.Println("\nTo activate, ensure the shim directory is at the front of your $PATH:")
		fmt.Printf("  export PATH=\"%s:$PATH\"\n", effectiveDir)
	case "uninstall":
		err := mgr.Uninstall(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to uninstall shims: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Airlock: successfully removed shims from %s\n", effectiveDir)
	case "list":
		shims, err := mgr.List(targetDir)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to list shims: %v\n", err)
			os.Exit(1)
		}
		fmt.Printf("Airlock Shims (%s):\n", effectiveDir)
		for _, s := range shims {
			status := "[not installed]"
			if s.Installed {
				status = "[active]"
			}
			fmt.Printf("  • %-10s %s\n", s.Tool, status)
		}
	default:
		fmt.Fprintf(os.Stderr, "airlock: unknown shim action %q\n", action)
		os.Exit(1)
	}
}

func handleMCP(args []string) {
	server := mcp.NewServer(os.Stdin, os.Stdout, mcp.WithVersion(version))
	if err := server.Serve(context.Background()); err != nil {
		fmt.Fprintf(os.Stderr, "airlock mcp: server error: %v\n", err)
		os.Exit(1)
	}
}


