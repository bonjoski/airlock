package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/bonjoski/airlock/pkg/vet"
)

func handleVet(args []string) {
	fs := flag.NewFlagSet("airlock vet", flag.ExitOnError)
	strict := fs.Bool("strict", true, "Fail closed (exit 1) on High or Critical risk findings")
	workspace := fs.String("workspace", "", "Override workspace directory to inspect")
	jsonOut := fs.Bool("json", false, "Output report as structured JSON")
	vetTool := fs.String("vetpkg", "", "Optional path to external vetpkg / argus binary analyzer")

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
		flagArgs = args
	}

	_ = fs.Parse(flagArgs)

	ws := *workspace
	if ws == "" {
		cwd, err := os.Getwd()
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock vet: failed to get working directory: %v\n", err)
			os.Exit(1)
		}
		ws = cwd
	}

	absWS, err := filepath.Abs(ws)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock vet: invalid workspace path: %v\n", err)
		os.Exit(1)
	}

	engine := vet.NewEngine(vet.Config{
		StrictMode:   *strict,
		ExternalTool: *vetTool,
	})

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	report, err := engine.Inspect(ctx, cmdArgs, absWS)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock vet: inspection failed: %v\n", err)
		os.Exit(1)
	}

	if *jsonOut {
		data, _ := json.MarshalIndent(report, "", "  ")
		fmt.Println(string(data))
	} else {
		fmt.Println("Argus Supply Chain Static Analysis & Threat Inspection")
		fmt.Println("=======================================================")
		fmt.Printf("Workspace Root: %s\n", absWS)
		if len(cmdArgs) > 0 {
			fmt.Printf("Target Command: %s\n", strings.Join(cmdArgs, " "))
		}
		fmt.Printf("Duration:       %d ms\n", report.DurationMs)
		fmt.Printf("Overall Risk:   %s\n", report.MaxRisk)
		fmt.Println()

		if len(report.Findings) == 0 {
			fmt.Println("  ✓ PASS: Zero supply-chain threats or suspicious lifecycle hooks detected.")
		} else {
			for _, f := range report.Findings {
				var sym string
				switch f.Severity {
				case vet.RiskCritical, vet.RiskHigh:
					sym = "❌"
				case vet.RiskMedium:
					sym = "⚠️"
				default:
					sym = "ℹ️"
				}
				fmt.Printf("  %s [%s] %s: %s\n", sym, f.Severity, f.RuleID, f.Description)
				if f.Target != "" {
					fmt.Printf("         Target: %s\n", f.Target)
				}
				if f.Remediation != "" {
					fmt.Printf("         Action: %s\n", f.Remediation)
				}
			}
		}
		fmt.Println("-------------------------------------------------------")
		if report.BlockExecution {
			fmt.Printf("Status: BLOCKED (%d finding(s) require remediation before execution)\n", len(report.Findings))
		} else {
			fmt.Println("Status: PASSED")
		}
	}

	if report.BlockExecution {
		os.Exit(1)
	}
}
