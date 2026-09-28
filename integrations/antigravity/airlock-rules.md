# Antigravity Agent Rule: Airlock Workstation Sandboxing 🛡️

## Policy Directives for Antigravity AI Agents

When executing shell commands, installing packages, or modifying codebase dependencies:

### 1. Mandatory Sandboxed Execution
- All package installation and dependency management commands (`npm install`, `pnpm add`, `yarn add`, `pip install`, `cargo add`, `uv pip install`, `bun add`) MUST run inside the Airlock zero-trust sandbox.
- When calling CLI tools directly: `airlock run -- <command> [args...]` or `airlock <command> [args...]`.
- When using the Model Context Protocol (MCP), invoke the `airlock_exec` tool with `{ "command": "...", "workspace": "..." }`.

### 2. Pre-Execution Static Analysis (Argus / Vet)
- Before introducing new third-party dependencies from unvetted sources, use `--vet` or `--vet-strict` (or the `airlock_vet` MCP tool) to inspect manifests and detect typosquats:
  `airlock --vet npm install <package>`
- Review any High or Critical findings. Block execution if malicious install scripts (`preinstall`, `setup.py`, `build.rs`) are detected.

### 3. Zero-Trust Workspace & Host Invariant Protection
- **Host Secrets**: Access to `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, macOS Keychain, and `/var/run/docker.sock` is strictly denied by the kernel.
- **Git Hook Protection**: Write access to `.git/hooks` is blocked to prevent persistence backdoors.
- **Secret Masking**: Read access to `.env*`, `*.pem`, and `*.key` files is blocked within the sandbox.
- **Fail-Closed Network**: Direct raw socket egress is dropped by the kernel; external outbound traffic is routed strictly through the supervisor's ephemeral forward proxy to whitelisted package registries.

### 4. Non-Interactive Autonomous Loops
- In headless agent pipelines, pass `--non-interactive` to bypass interactive PTY capability prompts and ensure pipe closures.

---

## 🛠️ MCP Capabilities Overview

### Tools
* `airlock_exec`: Executes commands inside OS-level sandbox confinement.
* `airlock_vet`: Performs Argus static analysis to detect typosquats and suspicious hooks.
* `airlock_policy_check`: Tests whether domains, paths, or env vars comply with `airlock.yaml`.

### Resources
* `airlock://audit/recent`: Reads the last 50 telemetry events from `~/.airlock/audit.log`.
* `airlock://policy/active`: Inspects the active declarative policy and immutable guardrails.
* `airlock://health`: Returns sandbox backend health and isolation capability metrics.

### Prompts
* `security_review`: Guides the agent to perform a complete code security review.
* `pre_install_audit`: Evaluates supply-chain risks for target package dependencies.
* `sandbox_troubleshoot`: Troubleshoots sandbox denials and proxy blocks.
