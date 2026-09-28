package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"os/signal"
	"strings"
	"syscall"
	"time"

	"github.com/bonjoski/airlock/pkg/audit"
)

func handleAudit(args []string) {
	if len(args) == 0 {
		printAuditUsage()
		os.Exit(0)
	}

	sub := args[0]
	subArgs := args[1:]

	switch sub {
	case "list":
		handleAuditList(subArgs)
	case "tail":
		handleAuditTail(subArgs)
	case "stats":
		handleAuditStats(subArgs)
	case "export":
		handleAuditExport(subArgs)
	case "help", "-h", "--help":
		printAuditUsage()
		os.Exit(0)
	default:
		fmt.Fprintf(os.Stderr, "airlock audit: unknown subcommand %q\n\n", sub)
		printAuditUsage()
		os.Exit(1)
	}
}

func printAuditUsage() {
	fmt.Println(`Airlock Audit — Telemetry & Security Violation Query Engine

Usage:
  airlock audit list [--limit N] [--type TYPE] [--status STATUS] [--search STR] [--since TIME] [--json]
  airlock audit tail [-n N] [-f]
  airlock audit stats [--since TIME] [--json]
  airlock audit export [--format json|csv] [--output FILE]

Subcommands:
  list    Display structured audit records matching filters
  tail    Stream and follow real-time audit logs
  stats   Aggregate telemetry metrics (executions, egress denials, DNS tunneling, top domains)
  export  Export audit log in JSON or CSV format`)
}

func parseSinceTime(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, nil
	}
	s = strings.TrimSpace(s)
	if dur, err := time.ParseDuration(s); err == nil {
		return time.Now().Add(-dur), nil
	}
	if t, err := time.Parse(time.RFC3339, s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02 15:04:05", s); err == nil {
		return t, nil
	}
	if t, err := time.Parse("2006-01-02", s); err == nil {
		return t, nil
	}
	return time.Time{}, fmt.Errorf("invalid time/duration format: %s", s)
}

func handleAuditList(args []string) {
	fs := flag.NewFlagSet("airlock audit list", flag.ExitOnError)
	limit := fs.Int("limit", 0, "Maximum number of records to return")
	recType := fs.String("type", "", "Filter by record type (exec, network, dns, security)")
	status := fs.String("status", "", "Filter by status (allow, deny, blocked)")
	search := fs.String("search", "", "Filter by substring in command, host, domain, details")
	sinceStr := fs.String("since", "", "Filter by time/duration (e.g. 1h, 24h, 2026-09-28T00:00:00Z)")
	asJSON := fs.Bool("json", false, "Output results as JSON")
	_ = fs.Parse(args)

	engine, err := audit.DefaultQueryEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	sinceTime, err := parseSinceTime(*sinceStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	filter := audit.Filter{
		RecordType: *recType,
		Status:     *status,
		Search:     *search,
		Since:      sinceTime,
		Limit:      *limit,
	}

	records, err := engine.Query(filter)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: failed to query logs: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(records); err != nil {
			fmt.Fprintf(os.Stderr, "airlock audit: failed to output JSON: %v\n", err)
			os.Exit(1)
		}
		return
	}

	if len(records) == 0 {
		fmt.Println("No audit records matching criteria found.")
		return
	}

	fmt.Printf("%-19s  %-18s  %-7s  %s\n", "TIMESTAMP", "TYPE", "STATUS", "SUMMARY")
	fmt.Printf("%-19s  %-18s  %-7s  %s\n", "-------------------", "------------------", "-------", "----------------------------------------")
	for _, rec := range records {
		fmt.Println(audit.FormatEntryLine(rec))
	}
}

func handleAuditTail(args []string) {
	fs := flag.NewFlagSet("airlock audit tail", flag.ExitOnError)
	lines := fs.Int("n", 10, "Number of preceding lines to show")
	fs.IntVar(lines, "lines", 10, "Number of preceding lines to show")
	follow := fs.Bool("f", false, "Follow log stream in real time")
	fs.BoolVar(follow, "follow", false, "Follow log stream in real time")
	_ = fs.Parse(args)

	engine, err := audit.DefaultQueryEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	ctx, cancel := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer cancel()

	if err := engine.Tail(ctx, *lines, *follow, os.Stdout); err != nil && err != context.Canceled {
		fmt.Fprintf(os.Stderr, "airlock audit: tail error: %v\n", err)
		os.Exit(1)
	}
}

func handleAuditStats(args []string) {
	fs := flag.NewFlagSet("airlock audit stats", flag.ExitOnError)
	asJSON := fs.Bool("json", false, "Output statistics as JSON")
	sinceStr := fs.String("since", "", "Filter statistics by time/duration (e.g. 1h, 24h)")
	_ = fs.Parse(args)

	engine, err := audit.DefaultQueryEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	sinceTime, err := parseSinceTime(*sinceStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	stats, err := engine.Stats(audit.Filter{Since: sinceTime})
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: failed to calculate stats: %v\n", err)
		os.Exit(1)
	}

	if *asJSON {
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(stats); err != nil {
			fmt.Fprintf(os.Stderr, "airlock audit: failed to output JSON: %v\n", err)
			os.Exit(1)
		}
		return
	}

	fmt.Println("Airlock Audit Telemetry Summary")
	fmt.Println("===============================")
	fmt.Printf("Total Records:               %d\n", stats.TotalRecords)
	fmt.Printf("Total Executions:            %d\n", stats.TotalExecutions)
	fmt.Printf("Allowed Network Egress:      %d\n", stats.AllowedEgressAttempts)
	fmt.Printf("Denied Network Egress:       %d\n", stats.DeniedEgressAttempts)
	fmt.Printf("Allowed DNS Queries:         %d\n", stats.AllowedDNSQueries)
	fmt.Printf("Blocked DNS Tunneling:       %d\n", stats.BlockedDNSTunneling)
	fmt.Printf("Security Policy Violations:  %d\n", stats.SecurityEvents)

	fmt.Println("\nTop Accessed Domains:")
	if len(stats.TopDomains) == 0 {
		fmt.Println("  (none)")
	} else {
		for i, dom := range stats.TopDomains {
			fmt.Printf("  %d. %-30s (%d)\n", i+1, dom.Domain, dom.Count)
		}
	}

	fmt.Println("\nTop Executed Commands:")
	if len(stats.TopCommands) == 0 {
		fmt.Println("  (none)")
	} else {
		for i, cmd := range stats.TopCommands {
			fmt.Printf("  %d. %-30s (%d)\n", i+1, cmd.Command, cmd.Count)
		}
	}
}

func handleAuditExport(args []string) {
	fs := flag.NewFlagSet("airlock audit export", flag.ExitOnError)
	format := fs.String("format", "json", "Export format: json or csv")
	output := fs.String("output", "", "Output file path (default stdout)")
	recType := fs.String("type", "", "Filter by record type (exec, network, dns, security)")
	status := fs.String("status", "", "Filter by status (allow, deny, blocked)")
	sinceStr := fs.String("since", "", "Filter by time/duration")
	_ = fs.Parse(args)

	engine, err := audit.DefaultQueryEngine()
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	sinceTime, err := parseSinceTime(*sinceStr)
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: %v\n", err)
		os.Exit(1)
	}

	records, err := engine.Query(audit.Filter{
		RecordType: *recType,
		Status:     *status,
		Since:      sinceTime,
	})
	if err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: failed to query records: %v\n", err)
		os.Exit(1)
	}

	outWriter := os.Stdout
	if *output != "" {
		f, err := os.Create(*output)
		if err != nil {
			fmt.Fprintf(os.Stderr, "airlock audit: failed to create output file %s: %v\n", *output, err)
			os.Exit(1)
		}
		defer f.Close()
		outWriter = f
	}

	exportFmt := audit.ExportFormat(strings.ToLower(*format))
	if err := engine.Export(records, exportFmt, outWriter); err != nil {
		fmt.Fprintf(os.Stderr, "airlock audit: export failed: %v\n", err)
		os.Exit(1)
	}

	if *output != "" {
		fmt.Printf("Exported %d audit records to %s (%s)\n", len(records), *output, exportFmt)
	}
}
