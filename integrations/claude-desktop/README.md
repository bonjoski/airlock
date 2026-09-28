# Claude Desktop Integration with Airlock MCP 🛡️

Integrate Airlock with Anthropic's Claude Desktop application via the Model Context Protocol (MCP) to execute shell commands, install third-party packages, and audit code safely within a zero-trust operating system sandbox.

---

## 🚀 Quick Setup

### 1. Locate Claude Desktop Configuration File

- **macOS**: `~/Library/Application Support/Claude/claude_desktop_config.json`
- **Linux**: `~/.config/Claude/claude_desktop_config.json`
- **Windows**: `%APPDATA%\Claude\claude_desktop_config.json`

### 2. Add Airlock Server Configuration

Copy the contents of [`claude_desktop_config.json`](claude_desktop_config.json) into your Claude Desktop configuration:

```json
{
  "mcpServers": {
    "airlock": {
      "command": "airlock",
      "args": ["mcp"]
    }
  }
}
```

*Note:* If `airlock` is installed in a non-standard path, provide the absolute path to the binary (e.g. `"/usr/local/bin/airlock"` or `"/Users/<username>/.airlock/bin/airlock"`).

### 3. Restart Claude Desktop

Restart Claude Desktop to load the MCP server. You will see a hammer icon 🔨 indicating that Airlock tools are connected.

---

## 🛠️ Available MCP Capabilities

### Tools
* **`airlock_exec`**: Safely executes commands inside kernel-level sandbox confinement (Apple Seatbelt / Linux bwrap + Landlock + Seccomp-BPF) with fail-closed egress filtering.
* **`airlock_vet`**: Pre-execution Argus static analysis to detect typosquatting (`crossenv`, `reqeusts`), obfuscated `setup.py`, and suspicious `build.rs` or Go/Ruby lifecycle scripts.
* **`airlock_policy_check`**: Verifies whether target paths, domains, or environment variables violate declarative policy (`airlock.yaml`) and zero-trust invariants.

### Resources
* **`airlock://audit/recent`**: View the latest 50 security telemetry and command execution events from `~/.airlock/audit.log`.
* **`airlock://policy/active`**: Inspect the currently discovered declarative policy rules and immutable security guardrails.
* **`airlock://health`**: Check system sandbox driver status, writable scratch locations, and shim health.

### Prompts
* **`security_review`**: Instructs Claude to perform a comprehensive security analysis on target files or manifests.
* **`pre_install_audit`**: Guides Claude through supply-chain risk assessment before installing any new dependency.
* **`sandbox_troubleshoot`**: Diagnoses egress proxy denials or filesystem access restrictions.
