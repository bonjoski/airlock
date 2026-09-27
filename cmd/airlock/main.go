// Command airlock is the entrypoint for the Airlock workstation sandbox.
package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/bonjoski/airlock/pkg/sandbox"
)

const version = "0.1.0"

var supportedShims = []string{
	"npm", "npx", "pnpm", "yarn", "pip", "pip3", "cargo", "uv", "bun",
}

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
		fmt.Printf("Airlock version %s\n", version)
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
		nonInteractive bool
		workspace      string
		scratchBase    string
	)

	fs.BoolVar(&airgap, "airgap", false, "Offline isolation")
	fs.BoolVar(&allowDirectNet, "net", false, "Permit direct external network")
	fs.StringVar(&allowDomains, "allow-domain", "", "Additional registry domains")
	fs.StringVar(&keepEnv, "keep-env", "", "Preserve environment variables")
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

	opts := sandbox.Options{
		WorkspaceRoot:  workspace,
		Airgap:         airgap,
		AllowDirectNet: allowDirectNet,
		AllowedDomains: extraDomains,
		KeepEnv:        keptEnvVars,
		NonInteractive: nonInteractive,
		ScratchBase:    scratchBase,
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
	exitCode, err := engine.Execute(ctx, cmdArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock: execution failed: %v\n", err)
		os.Exit(exitCode)
	}

	os.Exit(exitCode)
}

func handleShim(args []string) {
	if len(args) == 0 {
		fmt.Println("Usage: airlock shim [install|uninstall] [--target <dir>]")
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

	if targetDir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to get user home: %v\n", err)
			os.Exit(1)
		}
		targetDir = filepath.Join(home, ".airlock", "bin")
	}

	switch action {
	case "install":
		if err := os.MkdirAll(targetDir, 0755); err != nil {
			fmt.Fprintf(os.Stderr, "airlock: failed to create shim directory: %v\n", err)
			os.Exit(1)
		}

		for _, tool := range supportedShims {
			shimPath := filepath.Join(targetDir, tool)
			content := fmt.Sprintf("#!/bin/sh\n# Airlock transparent shim for %s\nexec airlock %s \"$@\"\n", tool, tool)
			if err := os.WriteFile(shimPath, []byte(content), 0755); err != nil {
				fmt.Fprintf(os.Stderr, "airlock: failed to write shim %s: %v\n", tool, err)
				os.Exit(1)
			}
		}
		fmt.Printf("Installed Airlock shims in: %s\n", targetDir)
		fmt.Println("To activate shims, prepend this directory to your PATH:")
		fmt.Printf("  export PATH=\"%s:$PATH\"\n", targetDir)

	case "uninstall":
		for _, tool := range supportedShims {
			shimPath := filepath.Join(targetDir, tool)
			if err := os.Remove(shimPath); err != nil && !os.IsNotExist(err) {
				fmt.Fprintf(os.Stderr, "airlock: warning: failed to remove shim %s: %v\n", tool, err)
			}
		}
		fmt.Printf("Uninstalled Airlock shims from: %s\n", targetDir)

	default:
		fmt.Printf("Unknown shim action: %s. Use 'install' or 'uninstall'.\n", action)
	}
}
