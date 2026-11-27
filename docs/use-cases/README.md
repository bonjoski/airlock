# 💡 Airlock End-User Use Cases & Recipes

> **Repository:** [`github.com/bonjoski/airlock`](https://github.com/bonjoski/airlock)  
> **Classification:** Developer Recipes & Task-Oriented Guides  
> **Source of Truth:** Authoritative Standard  

---

## Overview

**Airlock** provides ultra-fast (<15ms) kernel-level sandbox confinement for developers and autonomous AI coding agents using native operating system primitives (Apple Seatbelt on macOS, Landlock & bwrap on Linux, Job Objects on Windows).

This directory provides task-oriented recipes solving real-world security and supply-chain challenges.

---

## 📚 Recipe Catalog

| Recipe | Problem Addressed | Primary CLI Commands | Platform Engine |
| :--- | :--- | :--- | :--- |
| **[01. Fast Linter & Formatter Confinement](01-fast-linter-sandboxing.md)** | Run linters and formatters (`gofmt`, `ruff`, `eslint`) with sub-15ms cold start, read-only system access, and zero network egress. | `airlock run --profile linter -- <cmd>` | Seatbelt / Landlock |
| **[02. Sandboxed Package Managers (`npm`, `pip`, `cargo`)](02-sandboxed-package-managers.md)** | Execute package installs with strict filesystem boundaries, preventing post-install lifecycle scripts from reading `~/.ssh` or `~/.aws`. | `airlock run --profile node -- npm install`<br/>`airlock run --profile python -- pip install` | VFS & Proxy Confinement |
| **[03. Pre-Flight Command Policy Vetting (`airlock vet`)](03-preflight-policy-vetting.md)** | Inspect and audit what files, directories, and network sockets a command attempts to touch before allowing execution. | `airlock vet -- npm install lodash` | AST & Syscall Simulator |
| **[04. Strict No-Network Offline Code Exploration](04-offline-code-exploration.md)** | Allow autonomous research and refactoring agents to read repository files while mathematically blocking all exfiltration channels. | `airlock run --profile offline-reader -- <cmd>` | Kernel Egress Drop |
| **[05. Custom Declarative Sandbox Profiles](05-custom-sandbox-profiles.md)** | Compile and maintain custom declarative YAML profiles for specialized proprietary build pipelines. | `airlock profile create <name>`<br/>`airlock profile list` | Declarative Policy Engine |
| **[Confinement for Untrusted Agent Frameworks](confinement-for-untrusted-agent-frameworks.md)** | Run third-party local agent frameworks with immutable `PATH`, SSH/shell-rc persistence lock, ambient secret scrubbing, declared-API-only egress, and `airlock vet --strict` linting. | `airlock run --profile untrusted-agent --allow-egress api.anthropic.com -- <cmd>`<br/>`airlock vet --strict --dir .` | Seatbelt / Landlock / bwrap |
