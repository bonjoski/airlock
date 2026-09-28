# Airlock AI Agent & Editor Ecosystem Integrations 🤖

This directory contains ready-to-use client configurations, environment hooks, and policy rules for integrating Airlock into autonomous AI coding agents, IDEs, and developer toolchains.

---

## 📂 Client Integration Directories

| Integration | Type | Config File | Documentation |
| :--- | :---: | :--- | :--- |
| **Claude Desktop** | MCP (stdio) | [`claude-desktop/claude_desktop_config.json`](claude-desktop/claude_desktop_config.json) | [`claude-desktop/README.md`](claude-desktop/README.md) |
| **Cursor IDE** | MCP (stdio) | [`cursor/cursor_mcp.json`](cursor/cursor_mcp.json) | [`cursor/README.md`](cursor/README.md) |
| **Gemini CLI** | MCP (stdio) | [`gemini-cli/gemini_mcp_config.json`](gemini-cli/gemini_mcp_config.json) | [`gemini-cli/README.md`](gemini-cli/README.md) |
| **Antigravity (AGY)** | Rules & MCP | [`antigravity/mcp_settings.json`](antigravity/mcp_settings.json) | [`antigravity/airlock-rules.md`](antigravity/airlock-rules.md) |
| **VS Code** | Workspace | [`vscode/settings.json`](vscode/settings.json) | Embedded terminal `$PATH` configuration |
| **Shell Agent Env** | POSIX Shell | [`shell/airlock-agent-env.sh`](shell/airlock-agent-env.sh) | Sourced helper functions and prioritized `$PATH` |

---

## 🤖 Agent Framework Integration Patterns

### 1. Claude Desktop
Copy [`claude-desktop/claude_desktop_config.json`](claude-desktop/claude_desktop_config.json) into `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux).

### 2. Cursor Composer / Agent
Copy [`cursor/cursor_mcp.json`](cursor/cursor_mcp.json) into `.cursor/mcp.json` in your workspace, or add `airlock mcp` under Cursor Settings > Features > MCP.

### 3. Gemini CLI / Antigravity
Add [`gemini-cli/gemini_mcp_config.json`](gemini-cli/gemini_mcp_config.json) to `~/.gemini/antigravity-cli/mcp_config.json` and copy [`antigravity/airlock-rules.md`](antigravity/airlock-rules.md) to `.agents/rules/airlock.md`.

### 4. Claude Code / Codex / OpenHands / Aider
Source the agent environment in your entrypoint or task runner:

```bash
source integrations/shell/airlock-agent-env.sh
```

All standard package manager invocations (`npm install`, `pip install`, `cargo add`, etc.) will automatically execute confined inside the Airlock sandbox.
