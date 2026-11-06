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
	aiOutput := fs.Bool("ai", false, "Analyze diagnostic findings with sovereign Shield-protected AI")
	workspace := fs.String("workspace", "", "Override workspace root directory")
	fixMode := fs.Bool("fix", false, "Automatically repair misconfigured shims, permissions, and declarative policy")
	_ = fs.Parse(args)

	resolvedWorkspace := *workspace
	if resolvedWorkspace == "" {
		cwd, err := os.Getwd()
		if err == nil {
			resolvedWorkspace = sandbox.FindWorkspaceRoot(cwd)
		}
	}

	opts := doctor.Options{
		WorkspaceRoot: resolvedWorkspace,
	}

	detector := pty.NewDetector()
	useColor := detector.IsTerminal(os.Stdout)

	var fixReport *doctor.FixReport
	if *fixMode {
		var fixErr error
		fixReport, fixErr = doctor.AutoFix(context.Background(), opts)
		if fixErr != nil {
			fmt.Fprintf(os.Stderr, "airlock doctor: auto-remediation error: %v\n", fixErr)
		}
		if fixReport != nil && !*jsonOutput {
			fmt.Print(fixReport.FormatTerminal(useColor))
			fmt.Println()
		}
	}

	report, err := doctor.RunChecks(context.Background(), opts)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock doctor: diagnostic execution failed: %v\n", err)
		os.Exit(1)
	}

	if fixReport != nil {
		report.FixReport = fixReport
	}

	if *jsonOutput {
		data, err := report.ToJSON()
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock doctor: failed to serialize JSON report: %v\n", err)
			os.Exit(1)
		}
		fmt.Println(string(data))
	} else {
		fmt.Print(report.FormatTerminal(useColor))
	}

	if *aiOutput {
		advisory, err := report.GenerateAIAdvisory(context.Background())
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock doctor: AI advisory failed: %v\n", err)
		} else {
			fmt.Println("\n[Shield Protected AI Advisory]")
			fmt.Println(advisory)
		}
	}

	if !report.Healthy {
		os.Exit(1)
	}
	os.Exit(0)
}
