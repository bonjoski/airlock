# Airlock AI Agent & Editor Ecosystem Integrations 🤖

This directory contains integration wrappers, environment hooks, and configuration templates for integrating Airlock into autonomous AI coding agents and editor environments.

---

## 📂 Directory Overview

* **[`shell/airlock-agent-env.sh`](shell/airlock-agent-env.sh)**: Drop-in shell environment script prioritizing `~/.airlock/bin` in `$PATH` and exposing helper wrapper functions (`airlock_exec`, `airlock_airgap`).
* **[`antigravity/airlock-rules.md`](antigravity/airlock-rules.md)**: Agent instructions and policy rule template for Antigravity (AGY) agent loops.
* **[`vscode/settings.json`](vscode/settings.json)**: VS Code and Cursor workspace configuration setting integrated terminal `$PATH` to include Airlock shims automatically.

---

## 🤖 Agent Framework Integration Patterns

### 1. Claude Code / Codex / OpenHands / Aider
Source the agent environment in your entrypoint or task runner:

```bash
source integrations/shell/airlock-agent-env.sh
```

All standard package manager invocations (`npm install`, `pip install`, `cargo add`, etc.) will automatically execute confined inside the Airlock sandbox.

### 2. Cursor / VS Code
Copy `integrations/vscode/settings.json` into `.vscode/settings.json` in your workspace. Terminal sessions opened in Cursor or VS Code will automatically inherit the Airlock shims.

### 3. Antigravity Agent Rules
Add `integrations/antigravity/airlock-rules.md` to your agent rules configuration (e.g. `.agents/rules/airlock.md`).
