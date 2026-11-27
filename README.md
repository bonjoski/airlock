# Airlock 🛡️

> **Minimalist Zero-Trust Workstation Sandbox for Untrusted Package Installs & Autonomous AI Coding Agents**  
> *Target Startup Overhead: <15ms (Measured: ~7.9ms) | Footprint: Zero-VM / Zero-Daemon | Platform: macOS, Linux & Windows*  

[![CI](https://github.com/bonjoski/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/airlock/actions/workflows/ci.yml)
[![SLSA 2](https://slsa.dev/images/gh-badge-level2.svg)](https://slsa.dev)
[![Release](https://img.shields.io/github/v/release/bonjoski/airlock?color=blue)](https://github.com/bonjoski/airlock/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)
[![Sigstore Cosign](https://img.shields.io/badge/Signed_with-Sigstore_Cosign-blueviolet.svg)](https://docs.sigstore.dev)

Airlock (`airlock`) provides sub-8ms, zero-VM process confinement for package managers and build tools across major ecosystems (`npm`, `pnpm`, `yarn`, `bun`, `pip`, `uv`, `cargo`, `go`, `mvn`, `gradle`, `dotnet`, `nuget`, `gem`, `bundle`, `swift`, `pod`, `helm`) and autonomous AI coding agents (Claude Desktop, Cursor, Gemini CLI, Antigravity) directly on developer workstations.

---

## 🛑 Why Airlock is Needed (The Problem)

### 1. Package Managers Run Arbitrary Code as You
Every modern package manager executes arbitrary code during installation and build routines:
* **Node.js**: `preinstall`, `postinstall`, `prepare` lifecycle scripts in `package.json`
* **Python**: Dynamic execution inside `setup.py` / `pip install`
* **Rust**: Unrestricted host build scripts in `build.rs`
* **Ruby**: Native C extension builders in `extconf.rb` / `Rakefile`

A single typosquatted, hijacked, or malicious dependency executes with **your exact user permissions**, giving attackers instant access to:
* **Host Secrets:** `~/.ssh/id_rsa`, `~/.aws/credentials`, `~/.gnupg`, `~/.kube/config`, `~/.config/gcloud`
* **Workspace Secrets:** `.env`, `.env.local`, `*.pem`, database credentials, private API keys
* **Persistent Backdoors:** Writing malicious git hooks into `.git/hooks/pre-commit` or poisoning `.git/config`
* **Network Exfiltration:** Bypassing advisory proxy settings via raw TCP sockets, DNS tunneling, or reverse shells
* **Host Daemon Escapes:** Accessing `/var/run/docker.sock` to spawn privileged root containers

### 2. AI Coding Agents Execute Shell Loops on Your Machine
Autonomous coding agents (Claude Desktop, Cursor, Gemini CLI, Antigravity, Claude Code) routinely run terminal commands and install dependencies to solve programming tasks. Without kernel sandboxing, a hallucinated package name or an indirect prompt injection attack in untrusted code can compromise your entire system.

### 3. Traditional Sandboxes & VMs Don't Work for Workstations
* **Docker / VMs:** Heavyweight, slow startup (>2-5s), broken filesystem permissions, cold package cache penalties (>90s downloads), and complex port forwarding.
* **Advisory Env (`HTTP_PROXY`):** Malicious binaries simply ignore environment variables and make direct raw socket connections or UDP DNS tunneling queries.

---

## 💡 How Airlock Solves It

Airlock enforces **Kernel-Level Zero-Trust Confinement** without VMs, daemons, or performance degradation:

```mermaid
flowchart TD
    subgraph Host["Developer Workstation & AI Runtime"]
        User["Developer Shell / AI Coding Agent"]
        CLI["Airlock CLI (airlock / airlock-mcp)"]
    end

    subgraph DefenseLayer["Airlock Zero-Trust Protection Layer"]
        PTY["1. Dedicated PTY & Console Detection<br/>(Neutralizes TIOCSTI terminal injection)"]
        ENV["2. Zero-Trust Environment Scrubbing<br/>(Drops cloud tokens, AWS/GCP keys, DB URIs)"]
        PROXY["3. Ephemeral Forward Proxy & DNS Interceptor<br/>(RFC 1035 UDP forwarder; NXDOMAIN on DNS tunnels)"]
        CACHE["4. Read-Only Host Package Caches<br/>(~/.npm, ~/.cache/pip, ~/.cargo + staging write-layer)"]
        SCRATCH["5. Ephemeral Scratch Space<br/>(Private 0700 temporary directories)"]
        ARGUS["6. Argus Pre-Execution Static Vetting<br/>(Typosquats, obfuscated setup.py, build.rs backdoors)"]
        REDACT["7. Dynamic In-Stream Output Secret Redactor<br/>(Masks leaked API keys/tokens before stdout/LLM response)"]
    end

    subgraph OSKernel["Kernel Sandbox Engine"]
        DARWIN["macOS Seatbelt Engine (sandbox-exec)<br/>• Absolute {{.UserHome}} Path Interpolation<br/>• Deny Mach: Keychain, LaunchServices, Pasteboard, TCC<br/>• Deny /private/tmp launchd ssh-agent listeners<br/>• Deny .git write & .env* read in workspace<br/>• Kernel TCP egress strictly to 127.0.0.1:ProxyPort"]
        LINUX["Linux Engine (bwrap + Seccomp-BPF)<br/>• Unprivileged CLONE_NEWUSER & CLONE_NEWNET<br/>• Seccomp: Block io_uring, ptrace, TIOCSTI, bpf<br/>• Abstract Unix domain socket isolation (@X11, @dbus)"]
        WINDOWS["Windows Engine (Job Objects & Process Confinement)<br/>• Kill-on-close lifecycle guarantees<br/>• Active process limit fork-bomb prevention<br/>• Low integrity token isolation & proxy boundary"]
    end

    User --> CLI
    CLI --> PTY --> ENV --> PROXY --> CACHE --> SCRATCH --> ARGUS
    ARGUS --> OSKernel
    OSKernel --> REDACT
    REDACT --> Target["Confined Process Execution<br/>(npm install, pip install, cargo build, agent loop)"]
```

---

## 🌐 The Supply Chain Defense Suite

Airlock is the runtime confinement engine of the **Unified Supply Chain Defense Suite** created by [@bonjoski](https://github.com/bonjoski). Together, these three tools provide comprehensive defense-in-depth across the entire dependency lifecycle:

```mermaid
flowchart LR
    Dev["Developer / AI Agent<br/>(Intent to install/run dependencies)"]

    subgraph Tier1["Tier 1: Pre-Flight Gate"]
        Argus["🔍 Project Argus (vetpkg)<br/>• Provenance Verification<br/>• Slopsquatting / Hallucination Detection<br/>• Heuristic Risk Scoring (<800ms)"]
    end

    subgraph Tier2["Tier 2: Lockfile Governance"]
        Locksmith["🔐 Project Locksmith<br/>• Cryptographic Hash Pinning<br/>• Lockfile Tamper Protection<br/>• Dependency Tree Integrity & Policies"]
    end

    subgraph Tier3["Tier 3: Workstation Sandbox"]
        Airlock["🛡️ Project Airlock<br/>• Zero-VM Kernel Confinement (Seatbelt/bwrap)<br/>• Host & Workspace Secret Masking (~/.ssh, .env)<br/>• Ephemeral Proxy & DNS Interceptor<br/>• Dynamic Output Secret Redaction"]
    end

    Dev --> Tier1
    Tier1 -->|Verified Safe| Tier2
    Tier2 -->|Integrity Validated| Tier3
    Tier3 --> Runtime["Safe Local Execution & Build"]
```

### The Three Defense Pillars

| Tool | Focus & Purpose | Integration with Airlock |
| :--- | :--- | :--- |
| **[Argus](https://github.com/bonjoski/argus)** (`vetpkg`) | **Pre-Flight Provenance & Threat Vetting:** Queries upstream registries in real time to intercept hallucinated packages, typosquatting/slopsquatting, obfuscated `setup.py` scripts, and suspicious `build.rs` network logic before download. | Airlock embeds Argus rules directly into its pre-execution heuristic engine (`pkg/vet`, `--vet`, `--vetpkg`, and `airlock_vet` MCP tool). |
| **[Locksmith](https://github.com/bonjoski/locksmith)** | **Lockfile Integrity & Governance:** Validates, cryptographically pins, and audits multi-ecosystem lockfiles (`package-lock.json`, `pnpm-lock.yaml`, `Cargo.lock`, `poetry.lock`), ensuring immutable dependency graphs and preventing unauthorized upstream drift. | Locksmith ensures that *only* cryptographically verified packages enter the pipeline, while Airlock guarantees that their installation hooks cannot escape the workstation boundary. |
| **[Airlock](https://github.com/bonjoski/airlock)** | **Zero-VM Runtime Process Confinement:** Provides ultra-fast (<8ms) OS kernel sandbox isolation, secret masking (`~/.ssh`, `.env`), proxy egress enforcement, and in-stream secret redaction during dependency execution. | The final, unbypassable execution boundary protecting developer workstations and autonomous AI agent loops. |

---

## 🚀 Quickstart (Zero to Protected in 60 Seconds)

### Step 1: Install Airlock

#### Option A: Standalone POSIX Installer (macOS & Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/bonjoski/airlock/main/install.sh | sh
```

#### Option B: Homebrew (macOS & Linux)
```bash
brew tap bonjoski/tap
brew install airlock
```

#### Option C: Go Install
```bash
go install github.com/bonjoski/airlock/cmd/airlock@latest
go install github.com/bonjoski/airlock/cmd/airlock-mcp@latest
```

#### Option D: Windows Release Zip (Windows amd64 & arm64)
Download the latest `airlock_windows_amd64.zip` or `airlock_windows_arm64.zip` from [GitHub Releases](https://github.com/bonjoski/airlock/releases), extract `airlock.exe` and `airlock-mcp.exe`, and add to your User `PATH`.

---

### Step 2: Verify System Readiness (`airlock doctor`)
Run system diagnostics to verify kernel sandbox drivers, cache directories, and loopback proxies:
```bash
airlock doctor
```
```
Airlock Doctor — System Diagnostics & Health Report
==================================================
Platform:       darwin/arm64
Workspace Root: /Users/username/my-project

[Platform Sandbox Primitives]
  ✓ PASS sandbox-seatbelt-exec: macOS Seatbelt executable (sandbox-exec)
  ✓ PASS sandbox-seatbelt-profile: macOS Seatbelt profile synthesis (Seatbelt SBPL)

[Storage & Permissions]
  ✓ PASS storage-airlock-dir: Airlock state directory (~/.airlock) is writable
  ✓ PASS storage-npm-cache: Node / npm cache (~/.npm) is accessible
  ✓ PASS storage-cargo-cache: Rust / Cargo cache (~/.cargo/registry) is accessible
  ✓ PASS storage-scratch-dirs: Ephemeral scratch directory creation (mode 0700)

[Network & Proxy]
  ✓ PASS network-port-binding: Loopback socket binding (127.0.0.1) verified
  ✓ PASS network-dns-filter: In-process DNS filtering proxy active

[Toolchain Shims]
  ✓ PASS shims-path-configured: Toolchain shims active in $PATH (~/.airlock/bin)

Summary: 10 passed, 0 warnings, 0 failures (System HEALTHY)
```

---

### Step 3: Enable Transparent Package Manager Shims
Install lightweight shell shims for your toolchains (`npm`, `npx`, `pnpm`, `yarn`, `bun`, `pip`, `pip3`, `uv`, `cargo`, `go`, `mvn`, `gradle`, `dotnet`, `nuget`, `gem`, `bundle`, `swift`, `pod`, `helm`):
```bash
airlock shim install
```
Add `~/.airlock/bin` to your `~/.zshrc` or `~/.bashrc`:
```bash
export PATH="$HOME/.airlock/bin:$PATH"
```
🎉 **That's it!** All future install and build commands across supported ecosystems run automatically inside zero-trust kernel sandboxes with zero behavioral changes.

---

### Step 4: Run Commands Manually
You can also run commands explicitly through Airlock:
```bash
# Shorthand syntax
airlock npm install
airlock pip install -r requirements.txt
airlock cargo build
airlock bun add lodash

# Explicit syntax with custom allowed network domains
airlock run --allow-domain api.mycorp.internal -- npm install
```

---

## 💡 Core Use Cases & Recipes

Every primary developer use case is documented with copy-pasteable commands and verification steps in [**`docs/use-cases/`**](docs/use-cases/README.md):

| Use Case | Scenario & Quick Recipe | Full Guide |
| :--- | :--- | :--- |
| **Fast Linter & Formatter Confinement** | Run linters with sub-15ms overhead and zero network egress:<br/>`airlock run --profile linter -- gofmt -w .` | [Guide](docs/use-cases/01-fast-linter-sandboxing.md) |
| **Sandboxed Package Managers** | Isolate package installs and prevent credential theft from postinstall scripts:<br/>`airlock run --profile node -- npm install` | [Guide](docs/use-cases/02-sandboxed-package-managers.md) |
| **Pre-Flight Command & Hard-Boundary Linting (`--strict`)** | Inspect dependencies and lint compiled Seatbelt/Landlock profiles against Siren misconfiguration anti-patterns (exits `30` on findings):<br/>`airlock vet --strict --dir .` | [Guide](docs/use-cases/03-preflight-policy-vetting.md) |
| **Untrusted Agent Framework Confinement** | Jail third-party local agent runtimes with immutable `PATH`, SSH/rc lock, ambient secret scrub, and declared-API-only egress (`WAN=DENY` by default):<br/>`airlock run --profile untrusted-agent --allow-egress api.anthropic.com -- <cmd>` | [Guide](docs/use-cases/confinement-for-untrusted-agent-frameworks.md) |
| **Strict No-Network Code Exploration** | Enable autonomous agents to explore code while blocking exfiltration:<br/>`airlock run --profile offline-reader -- rg "TODO" src/` | [Guide](docs/use-cases/04-offline-code-exploration.md) |
| **Custom Declarative Sandbox Profiles** | Compile custom cross-platform Seatbelt/Landlock YAML profiles:<br/>`airlock profile create corporate-build --template standard-dev` | [Guide](docs/use-cases/05-custom-sandbox-profiles.md) |
| **Calm Confinement Explanations (`--why`)** | Inspect why a host credential or worktree path was blocked with progressive disclosure:<br/>`airlock explain ssh --why` | [CLI Contract](#calm-sandbox-denials--progressive-disclosure---why) |
| **Zero-Secret Opaque Leases & `BLPR-v1` Receipts (MCP)** | Redeem Locksmith opaque `secret_leases` inside `airlock_exec`, fail closed (`exit_code: 40`) on stdout leaks, and emit signed `BLPR-v1` DSSE receipts | [Recipe](#opaque-secret-leases--blpr-v1-provenance-receipts-ub-mcp-v1) |

### Opaque Secret Leases & `BLPR-v1` Provenance Receipts (`UB-MCP-v1`)

Autonomous AI coding agents can pass opaque Locksmith lease handles (`secret_leases`) into `airlock_exec` so raw credentials are redeemed directly over `LOCKSMITH_SOCKET`, zeroed in memory after execution, and **never enter the LLM context window**. If a sandboxed child attempts to echo a leased secret to stdout/stderr, Airlock scrubs the output completely and fails closed with a `UB-MCP-v1` `FixForwardError` (`code: "AIRLOCK_SECRET_LEAK_BLOCKED"`, `exit_code: 40`).

```json
{
  "name": "airlock_exec",
  "arguments": {
    "command": "go test ./billing/...",
    "workspace": "/path/to/repo",
    "secret_leases": ["lease_01JDX9N8Z..."],
    "session_id": "sess_01JDX9J00...",
    "emit_receipt": true
  }
}
```

When `FABRIAL_RECEIPT_DIR` is active, `airlock_exec` and `airlock_vet` atomically write signed `BLPR-v1` DSSE / in-toto Statement v1 receipts (`0600`, `os.OpenRoot` + `O_NOFOLLOW`, rejecting symlinked receipt directories fail-closed with `exit_code: 10`) using Locksmith's amortized session Ed25519 key (`sign_dsse`).

### Calm Sandbox Denials & Progressive Disclosure (`--why`)

When a confined script or AI agent hits a kernel boundary (such as reading `~/.ssh/id_rsa`), Airlock emits a calm ≤3-line UB-CLI-v2 Fix-Forward message instead of a cryptic `EPERM` traceback, and unlocks full OS confinement details via `--why` or `airlock explain`:

```bash
# Default calm output (<= 3 lines)
⚠ airlock: Airlock blocked read to ~/.ssh/id_rsa
  Fix:  airlock explain ssh --why
  Why:  Airlock prevented npm from accessing paths outside your workspace boundary. (re-run with --why or `airlock explain airlock_sandbox_denied` for details)

# Progressive disclosure (--why) or structured agent mode (--json)
airlock explain ssh --why
airlock explain sandbox --json
```

Available `airlock explain` topics: `sandbox`, `shims`, `seatbelt`, `landlock`, `ssh`, `worktree`.

---

---

## 🤖 AI Assistant & IDE Integration (Model Context Protocol)

Airlock includes a dedicated, high-performance **Model Context Protocol (MCP)** server (`airlock-mcp` or `airlock mcp`) providing autonomous AI coding agents with zero-trust execution, pre-execution threat vetting, and security policy introspection.

### 1. Claude Desktop Setup
Add the following to `~/Library/Application Support/Claude/claude_desktop_config.json` (macOS) or `~/.config/Claude/claude_desktop_config.json` (Linux):
```json
{
  "mcpServers": {
    "airlock": {
      "command": "airlock-mcp",
      "args": []
    }
  }
}
```

### 2. Cursor IDE Setup
Add the following to `.cursor/mcp.json` in your project workspace:
```json
{
  "mcpServers": {
    "airlock": {
      "command": "airlock-mcp",
      "args": []
    }
  }
}
```

### 3. Gemini CLI / Antigravity Setup
Add to your agent configuration settings:
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

---

### MCP Capabilities Reference

#### Tools
* **`airlock_exec`**: Safely executes shell commands inside sandboxed confinement with strict network domain filtering, directory masking, and dynamic secret redaction.
* **`airlock_vet`**: Runs Argus static heuristics to detect typosquatting packages, obfuscated `setup.py` scripts, and malicious `build.rs` outbound connections prior to execution.
* **`airlock_policy_check`**: Inspects whether specific egress domains, filesystem paths, or environment variables comply with active policy and invariant guardrails.

#### Resources
* **`airlock://audit/recent`**: Tail of the last 50 structured audit records (executions, denied egress attempts, blocked DNS tunneling).
* **`airlock://policy/active`**: Active project `airlock.yaml` policy, effective allowlists, and immutable security guardrails.
* **`airlock://health`**: Real-time system sandbox isolation status and kernel capability health.

#### Prompts
* **`security_review`**: Guides the AI assistant to perform comprehensive supply chain and security reviews on workspace code.
* **`pre_install_audit`**: Prompt template for evaluating third-party dependencies before installation.
* **`sandbox_troubleshoot`**: Diagnostic prompt for analyzing permission denials or blocked network domains.

---

## ⚡ Performance Benchmarks (< 15ms SLA Target)

Airlock is engineered for developer workstation use without noticeable latency overhead:

| Benchmark Operation | Target SLA | Measured Performance | Margin vs Target |
| :--- | :---: | :---: | :---: |
| **Sandbox Process Invocation Overhead** | `< 15.00 ms` | **7.88 ms / op** (~6.35 ms overhead vs 1.53 ms baseline) | **1.9x faster** |
| **Ephemeral Egress Proxy Handshake** | `< 2.00 ms` | **0.15 ms / op** (153.78 µs) | **13x faster** |
| **Proxy Data Throughput** | `> 500 MB/s` | **1,145.99 MB/s** (1.14 GB/s) | **2.3x higher** |
| **In-Process DNS Forwarder UDP Latency** | `< 5.00 ms` | **0.026 ms / op** (26.59 µs) | **188x faster** |
| **Argus Command Line Inspection** | `< 1.00 ms` | **0.052 ms / op** (52.43 µs) | **19x faster** |
| **Argus Manifest Parsing** | `< 5.00 ms / file` | **0.125 ms / op** (125.64 µs / 4 files) | **40x faster** |

*Benchmarked on Apple Silicon (M3 Max, macOS Darwin arm64) using `go test -v -bench=. ./tests/benchmark_test.go`.*

---

## 🛠️ CLI Subcommands Overview

### 1. `airlock run` (or `airlock <cmd>`)
Executes commands inside kernel-confined isolation:
```bash
airlock run -- npm test
airlock run --airgap -- pytest
airlock run --allow-domain api.openai.com -- python agent.py

# Run with specialized security execution profiles
airlock run --profile dev-agent -- claude
airlock run --profile untrusted-agent --allow-egress api.anthropic.com -- uvx <agent-framework>
airlock run --profile untrusted-agent --keyless-proxy 127.0.0.1:8443 -- uvx <agent-framework>
airlock run --profile mcp-gateway -- mcp-server
airlock run --profile web-worker -- node server.js
```

### 2. `airlock doctor`
Inspects host sandbox readiness, permissions, loopback proxy, and toolchain shims:
```bash
airlock doctor
airlock doctor --json
airlock doctor --workspace /path/to/project
```

### 3. `airlock audit`
Query, tail, and analyze security telemetry in `~/.airlock/audit.log`:
```bash
# List recent audit events
airlock audit list --limit 20

# Filter by type and status
airlock audit list --type network --status deny
airlock audit list --type dns --status deny

# Live tailing of all sandboxed activity
airlock audit tail -f

# Aggregated summary statistics
airlock audit stats

# Export audit trail to JSON or CSV for SIEM ingestion
airlock audit export --format json --output /tmp/audit.json
airlock audit export --format csv --output /tmp/audit.csv
```

### 4. `airlock init` & `airlock config`
Scaffold and validate declarative `airlock.yaml` workspace policies:
```bash
# Generate project policy
airlock init --type node      # Options: node, python, rust, go, java, dotnet, ruby, swift, container, general

# Validate policy against immutable security guardrails
airlock config validate --config ./airlock.yaml
```

#### Corporate Artifact Mirror Lockdown (Artifactory, Nexus)
Lock down all package managers to enterprise mirrors and block public egress:
```yaml
version: "1"
mode: "strict"
network:
  airgap: false
  allow_domains:
    - "artifactory.corp.internal"
    - "nexus.corp.internal"
  unknown_domain_action: "refused"
```

### 5. `airlock vet` (Argus Threat Engine & Siren Hard-Boundary Linter)
Run Argus static supply chain threat detection and post-compilation Siren sandbox profile linting across workspace manifests and compiled Seatbelt/Landlock policies:
```bash
# Scan current workspace and lint compiled sandbox profile (exits 30 on Siren misconfigs)
airlock vet --strict --dir .

# Output machine-readable JSON for CI/CD gates (includes siren_findings & fix_forward_error)
airlock vet --strict --dir . --json

# Progressive disclosure of all Siren findings and remediation steps
airlock vet --strict --dir . --why

# Vet command string before executing
airlock vet -- npm install suspicious-package
```

### 6. `airlock shim`
Manage transparent package manager shims:
```bash
airlock shim install
airlock shim list
airlock shim uninstall
```

### 7. `airlock profile list`
List and inspect built-in execution confinement profiles:
```bash
airlock profile list
```
Supported profiles:
- `standard`: Baseline hardened development sandbox with modern language registries permitted.
- `agent`: Autonomous coding assistants with anti-loopback and LLM API egress.
- `dev-agent`: Autonomous coding agents with strict credential isolation (`~/.ssh`, `~/.aws`, `~/.gnupg`, `~/.kube`, `~/.config/gh`).
- `untrusted-agent`: Strict confinement for third-party agent frameworks (immutable `PATH`, ambient secret & linker scrubbing, `~/.ssh/authorized_keys` / shell rc / LaunchAgents / `/etc/cron*` lockdown, default `WAN=DENY`, `--allow-egress` / loopback `--keyless-proxy`).
- `mcp-gateway`: Model Context Protocol servers/registries with anti-loopback and credential isolation (CVE-2026-125926).
- `web-worker`: Web application runtimes defended against child webshell execution (AntiFox defense).
- `strict`: Strict pre-execution AST vetting and minimal filesystem mutations.
- `airgap`: Total offline isolation (denies all outbound network traffic).
- `anti-loopback`: Confinement blocking localhost/127.0.0.1 probing (CVE-2026-25253).
- `default`: Baseline Airlock workstation confinement.

---

## 🛡️ 33/33 Adversarial Security Verification Battery

Every CI build executes an automated suite of adversarial attack simulations validating that root zero-trust invariants cannot be bypassed:

| Test ID | Test Name | Invariant | Attack Simulation | Status |
| :--- | :--- | :---: | :--- | :---: |
| **SEC-01** | `TestSEC01_SSHReadDenial` | **V-01** | Evaluates absolute path interpolation for `~/.ssh/id_rsa`. | **[PASS]** |
| **SEC-02** | `TestSEC02_RawSocketEgressDenial` | **V-02** | Raw outbound TCP socket connection attempting proxy bypass (`1.1.1.1:443`). | **[PASS]** |
| **SEC-03** | `TestSEC03_GitHookPersistenceDenial` | **V-03** | Trojan drop into `$PWD/.git/hooks/pre-commit`. | **[PASS]** |
| **SEC-04** | `TestSEC04_WorkspaceSecretDenial` | **V-04** | Reading workspace secrets (`.env`, `.env.local`, `*.pem`, `secrets.json`). | **[PASS]** |
| **SEC-05** | `TestSEC05_EnvSanitization` | **V-07** | POSIX environment allowlist scrubbing credentials and PATH sanitization. | **[PASS]** |
| **SEC-06** | `TestSEC06_DockerSocketDenial` | **V-06** | Accessing `/var/run/docker.sock` to trigger root container escape. | **[PASS]** |
| **SEC-07** | `TestSEC07_UsernsFailClosed` | **V-07** | Simulating disabled unprivileged user namespaces on hardened Linux. | **[PASS]** |
| **SEC-08** | `TestSEC08_ExitCodePropagation` | — | Precise propagation of exit codes and termination signals from sandbox child. | **[PASS]** |
| **SEC-09** | `TestSEC09_IOUringSeccompDenial` | **V-09** | Linux `sys_io_uring_setup`, `ptrace`, and `TIOCSTI` ioctl Seccomp-BPF denial. | **[PASS]** |
| **SEC-10** | `TestSEC10_AbstractSocketNetnsDetachment`| **V-09** | Connecting to abstract Unix domain sockets (`@X11`, `@dbus`) via `CLONE_NEWNET`. | **[PASS]** |
| **SEC-11** | `TestSEC11_ProxyDomainWhitelisting` | **V-02** | Ephemeral forward proxy TLS SNI whitelist enforcement. | **[PASS]** |
| **SEC-12** | `TestSEC12_ScratchOrphanCleanup` | **V-11** | Cryptographic `mkdtemp` (0700) and scavenger purge of abandoned dirs > 24h. | **[PASS]** |
| **SEC-13** | `TestSEC13_CacheStagingAndSync` | **V-12** | Read-only host cache mounts with ephemeral staging and verified sync-back. | **[PASS]** |
| **SEC-14** | `TestSEC14_NestedAirlockBypass` | — | `__AIRLOCK_ACTIVE=1` recursion bypass for nested toolchain invocations. | **[PASS]** |
| **SEC-15** | `TestSEC15_DNSTunnelingNeutralization` | **V-08** | In-process RFC 1035 UDP DNS forwarder returning `NXDOMAIN` on non-whitelisted domains. | **[PASS]** |
| **SEC-16** | `TestSEC16_AuditLogging` | — | Structured JSON-lines audit logging to `~/.airlock/audit.log` (0600 permissions). | **[PASS]** |
| **SEC-17** | `TestSEC17_ShimRecursionPrevention` | **V-14** | Transparent shell shims execution without recursion crashes. | **[PASS]** |
| **SEC-18** | `TestSEC18_ArgusStaticAnalysisHandoff` | — | Argus heuristic analysis and external `vetpkg` binary handoff. | **[PASS]** |
| **SEC-19** | `TestSEC19_TyposquattingInterception` | — | Pre-execution interception of known typosquats (`crossenv`, `reqeusts`). | **[PASS]** |
| **SEC-20** | `TestSEC20_RustBuildRsNetworkInterception`| — | Argus detection of outbound network sockets inside Rust `build.rs`. | **[PASS]** |
| **SEC-21** | `TestSEC21_SetupPyObfuscationInterception`| — | Interception of obfuscated base64 and reverse shell payloads in Python `setup.py`. | **[PASS]** |
| **SEC-22** | `TestSEC22_DeclarativeConfigDomainAllow` | — | Declarative `airlock.yaml` custom domain and wildcard allowlists. | **[PASS]** |
| **SEC-23** | `TestSEC23_DeclarativeConfigGuardrailDenial`| — | Guardrail rejection preventing `airlock.yaml` from overriding zero-trust boundaries. | **[PASS]** |
| **SEC-24** | `TestSEC24_InteractiveCapabilityGrantPrompt`| — | Dynamic interactive terminal prompts for unknown network domains. | **[PASS]** |
| **SEC-25** | `TestSEC25_ConfigInitAndValidation` | — | Policy scaffolding (`airlock init`) and validation against guardrails. | **[PASS]** |
| **SEC-26** | `TestSEC26_MCPSandboxConfinement` | — | Verifying MCP `airlock_exec` executes strictly inside zero-trust kernel sandbox. | **[PASS]** |
| **SEC-27** | `TestSEC27_MCPVetAndPolicyCheck` | — | MCP `airlock_vet` and `airlock_policy_check` tool threat detection and guardrails. | **[PASS]** |
| **SEC-28** | `TestSEC28_DoctorHealthyEnvironment` | — | `airlock doctor` diagnostic suite verifying platform, shims, and scratch health. | **[PASS]** |
| **SEC-29** | `TestSEC29_AuditQueryCapturesThreats` | — | `airlock audit` query engine indexing blocked egress, DNS tunneling, and CSV export. | **[PASS]** |
| **SEC-30** | `TestSEC30_MCPExtensions` | — | MCP protocol compliance for resources (`audit`, `policy`, `health`) and prompts. | **[PASS]** |
| **SEC-31** | `TestSEC31_ExtendedSupplyChainThreats` | — | Argus static analysis detection across Go, Ruby, and Obfuscated Shell pipelines. | **[PASS]** |
| **SEC-32** | `TestSEC32_SecretRedaction` | **V-24** | Dynamic in-stream secret redactor masking API keys/tokens across stdout & MCP. | **[PASS]** |
| **SEC-33** | `TestSEC33_AdvisoryRemediations_Adversarial` | **F1-F6** | GHSA-3vmj-37wh-72q5 hardening: cwd traversal defense, macOS trustd/securityd isolation, venv CA bundle access vs secret key denial, /tmp pnpm lock & launchd isolation, cache poisoning defense, and binary shadowing detection. | **[PASS]** |

---

## 🔏 Cryptographic Provenance (Sigstore Cosign & SLSA v1.0)

Every official Airlock release artifact includes cryptographic **SLSA v1.0 Build Provenance** and is signed using **Sigstore Cosign Keyless OIDC**. Verification is logged publicly in the Sigstore Rekor transparency log.

### 1. Verify SLSA Provenance (GitHub)
```bash
gh attestation verify airlock_v0.11.0_darwin_arm64.tar.gz --repo bonjoski/airlock
```

### 2. Verify Cosign Signature
```bash
cosign verify-blob \
  --bundle checksums.txt.bundle \
  --certificate-identity-regexp "^https://github.com/bonjoski/airlock/" \
  --certificate-oidc-issuer "https://token.actions.githubusercontent.com" \
  checksums.txt
```

### 3. Verify Offline with Soulcaster
```bash
soulcaster verify --attestation airlock.intoto.jsonl bin/airlock
```

---

## 🧪 Local Build & Verification

```bash
# Run unit and integration tests
make test

# Run adversarial security verification suite
make test-sec

# Run micro-benchmarks
make bench

# Build binaries (bin/airlock and bin/airlock-mcp)
make build

# Cross-compile release packages for macOS and Linux
make package
```

---

## 📄 License

MIT License — Copyright (c) 2026 Ben Skolmoski. See [LICENSE](LICENSE) for details.
