package main

import (
	"fmt"
	"io"
	"strings"

	"github.com/bonjoski/airlock/pkg/ux"
)

func runExplain(args []string, stdout, stderr io.Writer) int {
	asJSON := false
	showWhy := false
	topic := "sandbox"

	for _, a := range args {
		switch a {
		case "--json":
			asJSON = true
		case "--why":
			showWhy = true
		case "-h", "--help", "help":
			_, _ = fmt.Fprintln(stdout, "Usage: airlock explain [sandbox|shims|seatbelt|landlock|ssh|worktree] [--why] [--json]")
			return 0
		default:
			if !strings.HasPrefix(a, "-") {
				topic = strings.ToLower(strings.TrimSpace(a))
			}
		}
	}

	// Normalize common aliases and FixForwardError codes to canonical topics
	switch topic {
	case "", "airlock_sandbox_denied":
		topic = "sandbox"
	case "shim":
		topic = "shims"
	case "credentials", "secrets", "aws":
		topic = "ssh"
	case "git", "hooks":
		topic = "worktree"
	}

	explanations := map[string]*ux.FixForwardError{
		"sandbox": {
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_SANDBOX",
			Summary:        "Sub-15ms Tier 1 kernel confinement for package installs and AI coding loops",
			RemediationCmd: "airlock doctor",
			WhyOneLiner:    "Confines untrusted scripts to the active workspace while masking host credentials (~/.ssh, ~/.aws, .env).",
			DeepWhy:        "Airlock enforces default-deny OS kernel boundaries (macOS Seatbelt SBPL, Linux Landlock/bwrap + seccomp-BPF, Windows Job Objects) without spinning up a VM or daemon. Package lifecycle scripts (npm postinstall, pip setup.py, cargo build.rs) and AI coding agents execute inside the active workspace while host credentials, git hooks, and unauthorized egress remain unreachable.",
			References:     []string{"OWASP-LLM06", "CWE-250", "docs/use-cases/02-sandboxed-package-managers.md"},
			ExitCode:       0,
		},
		"shims": {
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_SHIMS",
			Summary:        "Transparent $PATH shims that automatically sandbox npm, pip, cargo, go, and uv",
			RemediationCmd: "airlock shim install",
			WhyOneLiner:    "Wraps package managers seamlessly so neither developers nor AI agents forget to invoke the sandbox.",
			DeepWhy:        "Running `airlock shim install` places tiny wrapper shims in ~/.airlock/bin for supported package managers. When placed ahead of system binaries on $PATH, every install or build command automatically runs inside Airlock kernel confinement with <15ms startup overhead and zero workflow changes.",
			References:     []string{"docs/use-cases/02-sandboxed-package-managers.md"},
			ExitCode:       0,
		},
		"seatbelt": {
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_SEATBELT",
			Summary:        "macOS Seatbelt (SBPL) kernel profile enforcement via sandbox-exec",
			RemediationCmd: "airlock doctor",
			WhyOneLiner:    "Blocks reads to ~/.ssh, ~/.aws, .env, Keychain Mach services, and direct raw sockets on macOS.",
			DeepWhy:        "On macOS, Airlock synthesizes a workspace-scoped Seatbelt Profile Language (SBPL) policy that denies Mach IPC to Keychain/Pasteboard/TCC, masks ~/.ssh and ~/.aws, blocks writes to .git/hooks, and restricts TCP egress exclusively to Airlock's ephemeral 127.0.0.1 forward proxy.",
			References:     []string{"CWE-250", "CWE-732"},
			ExitCode:       0,
		},
		"landlock": {
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_LANDLOCK",
			Summary:        "Linux Landlock LSM, unprivileged namespaces (bwrap), and seccomp-BPF confinement",
			RemediationCmd: "airlock doctor",
			WhyOneLiner:    "Isolates filesystem paths, network namespaces, and dangerous syscalls (io_uring, ptrace, TIOCSTI) on Linux.",
			DeepWhy:        "On Linux, Airlock combines Landlock / bubblewrap user+network namespaces with a strict seccomp-BPF filter blocking io_uring, ptrace, bpf, and TIOCSTI terminal injection. Abstract Unix domain sockets (@X11, @dbus) and host credentials outside the workspace are unreachable.",
			References:     []string{"CWE-250", "CWE-284"},
			ExitCode:       0,
		},
		"ssh": {
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_SSH",
			Summary:        "Airlock blocked read to ~/.ssh and host credential directories by design",
			RemediationCmd: "locksmith status",
			WhyOneLiner:    "Prevents compromised dependencies or prompt-injected agents from exfiltrating SSH, AWS, GPG, or kube keys.",
			DeepWhy:        "Postinstall scripts and prompt-injected coding agents routinely scan ~/.ssh/id_rsa, ~/.ssh/id_ed25519, ~/.aws/credentials, and launchd ssh-agent sockets. Airlock denies these reads at the kernel layer (returning EPERM). When a build legitimately needs an API token, lease a short-lived secret via `airlock run --lease-secret KEY -- <cmd>` backed by Locksmith.",
			References:     []string{"OWASP-LLM06", "CWE-522", "CWE-732"},
			ExitCode:       0,
		},
		"worktree": {
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_WORKTREE",
			Summary:        "Workspace and Git worktree boundary protection (.git/hooks & sibling isolation)",
			RemediationCmd: "airlock config validate",
			WhyOneLiner:    "Scopes writes strictly to the active worktree and blocks .git/hooks or .git/config persistence attacks.",
			DeepWhy:        "When multiple autonomous agents run concurrently across parallel Git worktrees, Airlock pins each sandbox to its own resolved workspace root and denies writes to .git/hooks and .git/config. Even if a dependency or subagent is compromised, it cannot poison sibling worktrees or plant persistent host git hooks.",
			References:     []string{"CWE-22", "CWE-250"},
			ExitCode:       0,
		},
	}

	entry, ok := explanations[topic]
	if !ok {
		ffe := &ux.FixForwardError{
			Tool:           "airlock",
			Code:           "AIRLOCK_EXPLAIN_UNKNOWN_TOPIC",
			Summary:        fmt.Sprintf("Unknown explain topic %q", topic),
			RemediationCmd: "airlock explain sandbox --why",
			WhyOneLiner:    "Available topics: sandbox, shims, seatbelt, landlock, ssh, worktree.",
			DeepWhy:        "Run `airlock explain <topic> --why` with one of: sandbox, shims, seatbelt, landlock, ssh, worktree.",
			ExitCode:       1,
		}
		_ = ffe.Render(stderr, asJSON, showWhy)
		return 1
	}

	if err := entry.Render(stdout, asJSON, showWhy); err != nil {
		return 1
	}
	return 0
}
