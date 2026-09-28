package main

import (
	"context"
	"flag"
	"fmt"
	"os"

	"github.com/bonjoski/airlock/pkg/doctor"
	"github.com/bonjoski/airlock/pkg/pty"
	"github.com/bonjoski/airlock/pkg/sandbox"
)

func handleDoctor(args []string) {
	fs := flag.NewFlagSet("airlock doctor", flag.ExitOnError)
	jsonOutput := fs.Bool("json", false, "Output diagnostic report in JSON format")
	workspace := fs.String("workspace", "", "Override workspace root directory")
	_ = fs.Parse(args)

	resolvedWorkspace := *workspace
	if resolvedWorkspace == "" {
		cwd, err := os.Getwd()
		if err == nil {
			resolvedWorkspace = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	report, err := doctor.RunAllChecks(context.Background(), resolvedWorkspace)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock doctor: diagnostic execution failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOutput {
		data, err := report.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock doctor: failed to serialize JSON report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		detector := pty.NewDetector()
		useColor := detector.IsTerminal(os.Stdout)
		fmt.Print(report.FormatTerminal(useColor))
	}

	if !report.Healthy {
		os.Exit(1)
	}
	os.Exit(0)
}
