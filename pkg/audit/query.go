package audit

import (
	"bufio"
	"context"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"sort"
	"strconv"
	"strings"
	"time"
)

// ExportFormat specifies the output format for audit log export.
type ExportFormat string

const (
	ExportJSON ExportFormat = "json"
	ExportCSV  ExportFormat = "csv"
)

// Entry is a normalized, queryable representation of an audit record.
type Entry struct {
	Timestamp  string    `json:"timestamp"`
	Time       time.Time `json:"time,omitempty"`
	Type       EventType `json:"type"`
	Action     string    `json:"action,omitempty"` // "ALLOW" or "DENY" for net/dns
	Command    string    `json:"command,omitempty"`
	Args       []string  `json:"args,omitempty"`
	Host       string    `json:"host,omitempty"`
	Port       int       `json:"port,omitempty"`
	Domain     string    `json:"domain,omitempty"`
	QueryType  string    `json:"query_type,omitempty"`
	Category   string    `json:"category,omitempty"`
	Details    string    `json:"details,omitempty"`
	ExitCode   int       `json:"exit_code,omitempty"`
	DurationMs int64     `json:"duration_ms,omitempty"`
	RawJSON    string    `json:"raw_json,omitempty"`
}

// Status computes the normalized status string ("ALLOW" or "DENY").
func (e Entry) Status() string {
	if e.Action != "" {
		return strings.ToUpper(e.Action)
	}
	if e.Type == EventSecurityViolation {
		return "DENY"
	}
	if e.Type == EventExecution {
		if e.ExitCode == 0 {
			return "ALLOW"
		}
		return "DENY"
	}
	return "ALLOW"
}

// Filter defines search and restriction criteria for audit log queries.
type Filter struct {
	RecordType string    `json:"record_type,omitempty"`
	Status     string    `json:"status,omitempty"`
	Search     string    `json:"search,omitempty"`
	Since      time.Time `json:"since,omitempty"`
	Limit      int       `json:"limit,omitempty"`
}

// DomainStat represents frequency count for a domain.
type DomainStat struct {
	Domain string `json:"domain"`
	Count  int    `json:"count"`
}

// CommandStat represents execution count for a command.
type CommandStat struct {
	Command string `json:"command"`
	Count   int    `json:"count"`
}

// StatsResult aggregates telemetry metrics across the audit dataset.
type StatsResult struct {
	TotalRecords          int           `json:"total_records"`
	TotalExecutions       int           `json:"total_executions"`
	AllowedEgressAttempts int           `json:"allowed_egress_attempts"`
	DeniedEgressAttempts  int           `json:"denied_egress_attempts"`
	AllowedDNSQueries     int           `json:"allowed_dns_queries"`
	BlockedDNSTunneling   int           `json:"blocked_dns_tunneling"`
	SecurityEvents        int           `json:"security_events"`
	TopDomains            []DomainStat  `json:"top_domains"`
	TopCommands           []CommandStat `json:"top_commands"`
}

// QueryEngine provides search, streaming, and aggregation capabilities over audit logs.
type QueryEngine struct {
	logPath string
}

// NewQueryEngine creates a QueryEngine pointing to the specified log path.
func NewQueryEngine(logPath string) *QueryEngine {
	return &QueryEngine{logPath: logPath}
}

// DefaultQueryEngine initializes a QueryEngine with ~/.airlock/audit.log.
func DefaultQueryEngine() (*QueryEngine, error) {
	path, err := DefaultAuditLogPath()
	if err != nil {
		return nil, err
	}
	return NewQueryEngine(path), nil
}

// ReadAll parses all records from the log file.
func (e *QueryEngine) ReadAll() ([]Entry, error) {
	file, err := os.Open(e.logPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	defer file.Close()

	var entries []Entry
	scanner := bufio.NewScanner(file)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if len(line) == 0 {
			continue
		}

		entry, err := parseRawLine(line)
		if err == nil {
			entries = append(entries, entry)
		}
	}

	return entries, scanner.Err()
}

func parseRawLine(line string) (Entry, error) {
	var raw map[string]interface{}
	if err := json.Unmarshal([]byte(line), &raw); err != nil {
		return Entry{}, err
	}

	ts, _ := raw["timestamp"].(string)
	typStr, _ := raw["type"].(string)
	typ := EventType(typStr)

	parsedTime, _ := time.Parse(time.RFC3339Nano, ts)
	if parsedTime.IsZero() {
		parsedTime, _ = time.Parse(time.RFC3339, ts)
	}

	entry := Entry{
		Timestamp: ts,
		Time:      parsedTime,
		Type:      typ,
		RawJSON:   line,
	}

	switch typ {
	case EventExecution:
		entry.Command, _ = raw["command"].(string)
		if rawArgs, ok := raw["args"].([]interface{}); ok {
			for _, a := range rawArgs {
				if s, ok := a.(string); ok {
					entry.Args = append(entry.Args, s)
				}
			}
		}
		if code, ok := raw["exit_code"].(float64); ok {
			entry.ExitCode = int(code)
		}
		if dur, ok := raw["duration_ms"].(float64); ok {
			entry.DurationMs = int64(dur)
		}
		if errStr, ok := raw["error"].(string); ok && errStr != "" {
			entry.Details = errStr
		}

	case EventNetworkEgress:
		entry.Host, _ = raw["host"].(string)
		if p, ok := raw["port"].(float64); ok {
			entry.Port = int(p)
		}
		entry.Action, _ = raw["action"].(string)
		entry.Details, _ = raw["reason"].(string)

	case EventDNSQuery:
		entry.Domain, _ = raw["domain"].(string)
		entry.QueryType, _ = raw["query_type"].(string)
		entry.Action, _ = raw["action"].(string)
		entry.Details, _ = raw["reason"].(string)

	case EventSecurityViolation:
		entry.Category, _ = raw["category"].(string)
		entry.Details, _ = raw["details"].(string)
	}

	return entry, nil
}

// Query filters the entries according to the provided criteria.
func (e *QueryEngine) Query(f Filter) ([]Entry, error) {
	all, err := e.ReadAll()
	if err != nil {
		return nil, err
	}

	var filtered []Entry
	for _, entry := range all {
		if !matchesFilter(entry, f) {
			continue
		}
		filtered = append(filtered, entry)
	}

	if f.Limit > 0 && len(filtered) > f.Limit {
		filtered = filtered[len(filtered)-f.Limit:]
	}

	return filtered, nil
}

func matchesFilter(entry Entry, f Filter) bool {
	// 1. RecordType filter
	if f.RecordType != "" {
		reqType := strings.ToLower(f.RecordType)
		switch reqType {
		case "exec", "execution":
			if entry.Type != EventExecution {
				return false
			}
		case "net", "network", "network_egress":
			if entry.Type != EventNetworkEgress {
				return false
			}
		case "dns", "dns_query":
			if entry.Type != EventDNSQuery {
				return false
			}
		case "security", "security_violation", "sec":
			if entry.Type != EventSecurityViolation {
				return false
			}
		default:
			if !strings.EqualFold(string(entry.Type), reqType) {
				return false
			}
		}
	}

	// 2. Status filter
	if f.Status != "" {
		reqStatus := strings.ToUpper(f.Status)
		entryStatus := strings.ToUpper(entry.Status())
		if reqStatus == "DENY" || reqStatus == "BLOCKED" || reqStatus == "FAIL" {
			if entryStatus != "DENY" && entryStatus != "FAIL" && entryStatus != "BLOCKED" {
				return false
			}
		} else if reqStatus == "ALLOW" || reqStatus == "PASS" {
			if entryStatus != "ALLOW" && entryStatus != "PASS" {
				return false
			}
		} else if !strings.EqualFold(entryStatus, f.Status) {
			return false
		}
	}

	// 3. Since filter
	if !f.Since.IsZero() {
		if !entry.Time.IsZero() && entry.Time.Before(f.Since) {
			return false
		}
	}

	// 4. Substring Search filter
	if f.Search != "" {
		searchTerm := strings.ToLower(f.Search)
		found := false
		if strings.Contains(strings.ToLower(entry.Command), searchTerm) ||
			strings.Contains(strings.ToLower(entry.Host), searchTerm) ||
			strings.Contains(strings.ToLower(entry.Domain), searchTerm) ||
			strings.Contains(strings.ToLower(entry.Category), searchTerm) ||
			strings.Contains(strings.ToLower(entry.Details), searchTerm) ||
			strings.Contains(strings.ToLower(entry.RawJSON), searchTerm) {
			found = true
		}
		for _, arg := range entry.Args {
			if strings.Contains(strings.ToLower(arg), searchTerm) {
				found = true
				break
			}
		}
		if !found {
			return false
		}
	}

	return true
}

// Stats computes aggregated metrics for entries matching the filter.
func (e *QueryEngine) Stats(f Filter) (*StatsResult, error) {
	entries, err := e.Query(f)
	if err != nil {
		return nil, err
	}

	stats := &StatsResult{
		TotalRecords: len(entries),
	}

	domainCounts := make(map[string]int)
	cmdCounts := make(map[string]int)

	for _, entry := range entries {
		switch entry.Type {
		case EventExecution:
			stats.TotalExecutions++
			if entry.Command != "" {
				cmdCounts[entry.Command]++
			}
		case EventNetworkEgress:
			if strings.EqualFold(entry.Status(), "ALLOW") {
				stats.AllowedEgressAttempts++
			} else {
				stats.DeniedEgressAttempts++
			}
			if entry.Host != "" {
				domainCounts[entry.Host]++
			}
		case EventDNSQuery:
			if strings.EqualFold(entry.Status(), "ALLOW") {
				stats.AllowedDNSQueries++
			} else {
				stats.BlockedDNSTunneling++
			}
			if entry.Domain != "" {
				domainCounts[entry.Domain]++
			}
		case EventSecurityViolation:
			stats.SecurityEvents++
		}
	}

	for dom, count := range domainCounts {
		stats.TopDomains = append(stats.TopDomains, DomainStat{Domain: dom, Count: count})
	}
	sort.Slice(stats.TopDomains, func(i, j int) bool {
		return stats.TopDomains[i].Count > stats.TopDomains[j].Count
	})

	for cmd, count := range cmdCounts {
		stats.TopCommands = append(stats.TopCommands, CommandStat{Command: cmd, Count: count})
	}
	sort.Slice(stats.TopCommands, func(i, j int) bool {
		return stats.TopCommands[i].Count > stats.TopCommands[j].Count
	})

	return stats, nil
}

// Export writes the provided entries to the writer in the chosen format.
func (e *QueryEngine) Export(entries []Entry, format ExportFormat, w io.Writer) error {
	return ExportEntries(entries, format, w)
}

// ExportEntries writes entries in JSON or CSV format to the writer.
func ExportEntries(entries []Entry, format ExportFormat, w io.Writer) error {
	switch format {
	case ExportJSON:
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(entries)

	case ExportCSV:
		cw := csv.NewWriter(w)
		defer cw.Flush()

		// Write header
		if err := cw.Write([]string{
			"timestamp", "type", "status", "command_or_host", "category", "details", "exit_code", "duration_ms",
		}); err != nil {
			return err
		}

		for _, entry := range entries {
			target := entry.Command
			if target == "" {
				target = entry.Host
			}
			if target == "" {
				target = entry.Domain
			}

			row := []string{
				entry.Timestamp,
				string(entry.Type),
				entry.Status(),
				target,
				entry.Category,
				entry.Details,
				strconv.Itoa(entry.ExitCode),
				strconv.FormatInt(entry.DurationMs, 10),
			}
			if err := cw.Write(row); err != nil {
				return err
			}
		}
		return nil

	default:
		return fmt.Errorf("unsupported export format: %s", format)
	}
}

// Tail streams the latest N records and follows new records if follow is true.
func (e *QueryEngine) Tail(ctx context.Context, n int, follow bool, w io.Writer) error {
	entries, err := e.ReadAll()
	if err != nil && !os.IsNotExist(err) {
		return err
	}

	start := 0
	if n > 0 && len(entries) > n {
		start = len(entries) - n
	}

	for _, entry := range entries[start:] {
		_, _ = fmt.Fprintln(w, FormatEntryLine(entry))
	}

	if !follow {
		return nil
	}

	file, err := os.Open(e.logPath)
	if err != nil {
		return err
	}
	defer file.Close()

	// Seek to end
	_, _ = file.Seek(0, io.SeekEnd)
	reader := bufio.NewReader(file)

	for {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		line, err := reader.ReadString('\n')
		if err != nil {
			if err == io.EOF {
				time.Sleep(50 * time.Millisecond)
				continue
			}
			return err
		}

		line = strings.TrimSpace(line)
		if len(line) == 0 {
			continue
		}

		entry, parseErr := parseRawLine(line)
		if parseErr == nil {
			_, _ = fmt.Fprintln(w, FormatEntryLine(entry))
		}
	}
}

// FormatEntryLine formats an entry for human-readable terminal line output.
func FormatEntryLine(e Entry) string {
	ts := e.Timestamp
	if len(ts) > 19 {
		ts = ts[:19]
	}

	switch e.Type {
	case EventExecution:
		cmdStr := e.Command
		if len(e.Args) > 0 {
			cmdStr = e.Command + " " + strings.Join(e.Args, " ")
		}
		return fmt.Sprintf("[%s] EXEC     %-24s exit=%d  dur=%dms", ts, cmdStr, e.ExitCode, e.DurationMs)
	case EventNetworkEgress:
		return fmt.Sprintf("[%s] NET      %-24s action=%s (%s)", ts, fmt.Sprintf("%s:%d", e.Host, e.Port), e.Status(), e.Details)
	case EventDNSQuery:
		return fmt.Sprintf("[%s] DNS      %-24s action=%s (%s)", ts, e.Domain, e.Status(), e.Details)
	case EventSecurityViolation:
		return fmt.Sprintf("[%s] SECURITY %-24s details=%s", ts, e.Category, e.Details)
	default:
		return fmt.Sprintf("[%s] %-8s %s", ts, e.Type, e.Details)
	}
}
