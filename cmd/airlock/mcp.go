package main

import (
	"context"
	"flag"
	"fmt"
	"os"
	"strings"

	"github.com/bonjoski/airlock/pkg/mcp"
)

func handleMCPWrap(args []string) {
	fs := flag.NewFlagSet("airlock mcp wrap", flag.ContinueOnError)

	var (
		lockfilePath string
		cacheDir     string
		allowNetwork string
		workspace    string
	)

	fs.StringVar(&lockfilePath, "lockfile", "", "Optional path to verified lockfile")
	fs.StringVar(&cacheDir, "cache-dir", "", "Path to immutable offline wheelhouse / package cache (default: ~/.airlock/mcp-cache)")
	fs.StringVar(&allowNetwork, "allow-network", "", "Optional allowlisted endpoint (host:port); default zero WAN egress")
	fs.StringVar(&workspace, "workspace", "", "Override workspace root directory")

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

	if err := fs.Parse(flagArgs); err != nil {
		fmt.Fprintf(os.Stderr, "airlock mcp wrap: %v\n", err)
		os.Exit(1)
	}

	if len(cmdArgs) == 0 {
		fmt.Fprintln(os.Stderr, "airlock mcp wrap: no command specified for execution (usage: airlock mcp wrap [flags] -- <cmd...>)")
		os.Exit(1)
	}

	launcher := mcp.NewLauncher(mcp.LauncherConfig{
		Lockfile:     lockfilePath,
		CacheDir:     cacheDir,
		AllowNetwork: allowNetwork,
		Workspace:    workspace,
		Stdin:        os.Stdin,
		Stdout:       os.Stdout,
		Stderr:       os.Stderr,
	})

	exitCode, err := launcher.Launch(context.Background(), cmdArgs)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock mcp wrap: %v\n", err)
		os.Exit(exitCode)
	}

	os.Exit(exitCode)
}
