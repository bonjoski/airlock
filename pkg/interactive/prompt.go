// Package interactive provides terminal prompts and capability grant management for Airlock.
package interactive

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"
	"time"
)

// Grant represents the decision result from a capability prompt.
type Grant int

const (
	GrantDeny Grant = iota
	GrantOnce
	GrantSession
	GrantPersist
)

// TerminalPrompter handles dynamic permission prompting in interactive TTY sessions.
type TerminalPrompter struct {
	In         io.Reader
	Out        io.Writer
	Timeout    time.Duration
	ConfigPath string
}

// NewTerminalPrompter creates a prompter with standard defaults.
func NewTerminalPrompter(configPath string, timeout time.Duration) *TerminalPrompter {
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	return &TerminalPrompter{
		In:         os.Stdin,
		Out:        os.Stderr,
		Timeout:    timeout,
		ConfigPath: configPath,
	}
}

// PromptDomain requests approval from the user when an unlisted domain is contacted.
func (p *TerminalPrompter) PromptDomain(domain string) Grant {
	msg := fmt.Sprintf("\n🔒 [Airlock Security Prompt]\n"+
		"   Process requested network egress to unlisted domain: %s\n"+
		"   [y] Allow once   [a] Allow for session   [s] Save to airlock.yaml   [n] Deny (default)\n"+
		"   Selection [y/a/s/N] (%.0fs timeout): ", domain, p.Timeout.Seconds())

	_, _ = fmt.Fprint(p.Out, msg)

	resultChan := make(chan Grant, 1)

	go func() {
		reader := bufio.NewReader(p.In)
		line, err := reader.ReadString('\n')
		if err != nil {
			resultChan <- GrantDeny
			return
		}
		trimmed := strings.ToLower(strings.TrimSpace(line))
		switch trimmed {
		case "y", "yes", "1":
			resultChan <- GrantOnce
		case "a", "all", "always", "session":
			resultChan <- GrantSession
		case "s", "save", "persist":
			resultChan <- GrantPersist
		default:
			resultChan <- GrantDeny
		}
	}()

	select {
	case grant := <-resultChan:
		switch grant {
		case GrantOnce:
			_, _ = fmt.Fprintf(p.Out, "   -> Granted: single request allowed.\n\n")
		case GrantSession:
			_, _ = fmt.Fprintf(p.Out, "   -> Granted: domain %q allowed for this session.\n\n", domain)
		case GrantPersist:
			_, _ = fmt.Fprintf(p.Out, "   -> Granted: saved %q to airlock policy.\n\n", domain)
		default:
			_, _ = fmt.Fprintf(p.Out, "   -> Denied by user.\n\n")
		}
		return grant
	case <-time.After(p.Timeout):
		_, _ = fmt.Fprintf(p.Out, "\n   -> Prompt timed out (%.0fs). Denied.\n\n", p.Timeout.Seconds())
		return GrantDeny
	}
}
