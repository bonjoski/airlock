# Airlock 🛡️

> **Minimalist Zero-Trust Workstation Sandbox for Untrusted Package Installs & Autonomous AI Coding Loops**

[![CI](https://github.com/bonjoski/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/airlock/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bonjoski/airlock?color=blue)](https://github.com/bonjoski/airlock/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Airlock (`airlock`, aliased as `boxpkg`) provides sub-15ms, zero-VM process confinement for package manager installations (`npm`, `pip`, `cargo`, `uv`, `bun`, `pnpm`, `yarn`) and AI coding agent execution directly on developer workstations.

---

## 🚀 Quick Install

### Option 1: Standalone Shell Installer (macOS & Linux)
```bash
curl -fsSL https://raw.githubusercontent.com/bonjoski/airlock/main/install.sh | sh
```

### Option 2: Homebrew (macOS & Linux)
```bash
brew install bonjoski/airlock/airlock
```

### Option 3: Go Install
```bash
go install github.com/bonjoski/airlock/cmd/airlock@latest
```

---

## ⚡ Benchmark SLA Performance Results

Airlock is engineered for ultra-low latency workstation execution, eliminating VM and container startup overhead while strictly maintaining kernel-level zero-trust invariants:

| Benchmark Operation | SLA Target | Measured Performance | Result |
| :--- | :---: | :---: | :---: |
| **Sandbox Process Invocation Overhead** | `< 15.00 ms` | **7.88 ms / op** (~6.35 ms overhead vs 1.53 ms baseline) | **PASSED (1.9x faster than SLA)** |
| **Ephemeral Egress Proxy Handshake** | `< 2.00 ms` | **0.15 ms / op** (153.78 µs) | **PASSED (13x faster than SLA)** |
| **Ephemeral Proxy Data Throughput** | `> 500 MB/s` | **1,145.99 MB/s** (1.14 GB/s) | **PASSED (2.3x throughput target)** |
| **In-Process DNS Forwarder UDP Latency** | `< 5.00 ms` | **0.026 ms / op** (26.59 µs) | **PASSED (188x faster than SLA)** |
| **Argus Command Line Inspection** | `< 1.00 ms` | **0.052 ms / op** (52.43 µs) | **PASSED (19x faster than SLA)** |
| **Argus Workspace Manifest Parsing** | `< 5.00 ms / file` | **0.125 ms / op** (125.64 µs / 4 files) | **PASSED (40x faster than SLA)** |

*Benchmarked on Apple Silicon (M3 Max, macOS Darwin arm64) using `go test -v -bench=. ./tests/benchmark_test.go`.*

---

## 🛠️ Complete Subcommands Reference

### 1. Execute Confined Commands (`airlock run` / Shorthand)
```bash
# Explicit syntax
airlock run -- npm install

# Direct shorthand syntax
airlock npm install
airlock pip install -r requirements.txt
airlock cargo build
airlock bun add lodash
```

### 2. System Diagnostics & Readiness (`airlock doctor`)
Diagnoses kernel sandbox drivers (Apple Seatbelt / Linux bwrap + Seccomp), shim installation status, scratch space permissions, audit logging, and declarative policy health:
```bash
# Human-readable terminal output with colored status checkmarks
airlock doctor

# Machine-readable JSON output
airlock doctor --json

# Diagnose a specific workspace directory
airlock doctor --workspace /path/to/project
```

### 3. Telemetry & Security Violation Query Engine (`airlock audit`)
Search, filter, tail, and export structured JSON-lines telemetry recorded in `~/.airlock/audit.log`:
```bash
# Display recent audit records (executions, egress requests, DNS queries, security violations)
airlock audit list --limit 25

# Filter by event type and status
airlock audit list --type network --status deny
airlock audit list --type dns --search tunnel
airlock audit list --type security

# Stream and follow live audit events in real-time
airlock audit tail -f

# Display aggregated telemetry statistics (executions, blocked egress, DNS tunneling, top domains)
airlock audit stats

# Export audit logs for SIEM or incident review
airlock audit export --format json --output /tmp/audit_export.json
airlock audit export --format csv --output /tmp/audit_export.csv

# Clear audit log
airlock audit clear
```

### 4. Declarative Policy Management (`airlock init` & `airlock config`)
```bash
# Scaffold a declarative airlock.yaml policy tailored to your project
airlock init --type node      # Options: node, python, rust, go, general

# Validate an existing policy against immutable security invariant guardrails
airlock config validate --config ./airlock.yaml
```

### 5. Transparent Toolchain Shims (`airlock shim`)
Intercept package managers automatically in your shell without typing `airlock`:
```bash
# Install shims in ~/.airlock/bin
airlock shim install

# List active shim status
airlock shim list

# Remove installed shims
airlock shim uninstall
```

### 6. Model Context Protocol Server (`airlock mcp`)
Launch the standalone Model Context Protocol stdio server for AI coding assistants:
```bash
airlock mcp
```

---

## 🤖 Model Context Protocol (MCP) Ecosystem

Airlock exposes native MCP server interfaces connecting directly to **Claude Desktop**, **Cursor IDE**, **Gemini CLI**, **Antigravity (AGY)**, and **Claude Code**.

### Tools
| Tool Name | Parameters | Description |
| :--- | :--- | :--- |
| **`airlock_exec`** | `command`, `args`, `workspace`, `config_path`, `airgap`, `allow_domains`, `keep_env`, `timeout_seconds` | Executes shell commands inside zero-trust OS sandbox confinement with fail-closed egress filtering and audit logging. |
| **`airlock_vet`** | `command`, `workspace`, `strict` | Performs Argus static analysis to detect typosquatting (`crossenv`, `reqeusts`), obfuscated `setup.py`, and suspicious `build.rs` network hooks. |
| **`airlock_policy_check`** | `workspace`, `config_path`, `domain`, `path`, `env_var` | Verifies whether target domains, filesystem paths, or environment variables comply with `airlock.yaml` and immutable guardrails. |

### Resources
| Resource URI | MIME Type | Description |
| :--- | :---: | :--- |
| **`airlock://audit/recent`** | `application/json` | Retrieves the latest 50 security telemetry and execution records from `~/.airlock/audit.log`. |
| **`airlock://policy/active`** | `application/json` | Discovers and formats active declarative policy rules and immutable security guardrails for the workspace. |
| **`airlock://health`** | `application/json` | Returns sandbox backend health, kernel capability status, and writable scratch availability. |

### Prompts
| Prompt Name | Arguments | Description |
| :--- | :--- | :--- |
| **`security_review`** | `target_path` (req), `context` | Instructs the AI assistant to perform a comprehensive security analysis on target files or manifests using Argus. |
| **`pre_install_audit`** | `package_name` (req), `ecosystem`, `version` | Guides the AI assistant through supply-chain risk assessment before installing any new package dependency. |
| **`sandbox_troubleshoot`** | `error_message` (req), `command`, `domain` | Assists in diagnosing and troubleshooting sandboxing denials, network proxy blocks, or environment variable issues. |

---

## 🛡️ 31/31 Adversarial Security Verification Suite

Every CI build runs automated adversarial attack simulations validating that root zero-trust invariants cannot be bypassed:

| ID | Test Name | Audit Ref | Attack Simulation | Status |
| :--- | :--- | :---: | :--- | :---: |
| **SEC-01** | `TestSEC01_SSHReadDenial` | **V-01** | Evaluates absolute path interpolation for `~/.ssh/id_rsa`. | **PASSED** |
| **SEC-02** | `TestSEC02_RawSocketEgressDenial` | **V-02** | Raw outbound TCP socket connection attempting proxy bypass (`1.1.1.1:443`). | **PASSED** |
| **SEC-03** | `TestSEC03_GitHookPersistenceDenial` | **V-03** | Trojan drop into `$PWD/.git/hooks/pre-commit`. | **PASSED** |
| **SEC-04** | `TestSEC04_WorkspaceSecretDenial` | **V-04** | Reading workspace secrets (`.env`, `.env.local`, `*.pem`, `secrets.json`). | **PASSED** |
| **SEC-05** | `TestSEC05_EnvSanitization` | **V-07** | POSIX environment allowlist scrubbing credentials and PATH sanitization. | **PASSED** |
| **SEC-06** | `TestSEC06_DockerSocketDenial` | **V-06** | Accessing `/var/run/docker.sock` to trigger root container escape. | **PASSED** |
| **SEC-07** | `TestSEC07_UsernsFailClosed` | **V-07** | Simulating disabled unprivileged user namespaces on hardened Linux. | **PASSED** |
| **SEC-08** | `TestSEC08_ExitCodePropagation` | — | Precise propagation of exit codes and termination signals from sandbox child. | **PASSED** |
| **SEC-09** | `TestSEC09_IOUringSeccompDenial` | **V-09** | Linux `sys_io_uring_setup`, `ptrace`, and `TIOCSTI` ioctl Seccomp-BPF denial. | **PASSED** |
| **SEC-10** | `TestSEC10_AbstractSocketNetnsDetachment`| **V-09** | Connecting to abstract Unix domain sockets (`@X11`, `@dbus`) via `CLONE_NEWNET`. | **PASSED** |
| **SEC-11** | `TestSEC11_ProxyDomainWhitelisting` | **V-02** | Ephemeral forward proxy TLS SNI whitelist enforcement. | **PASSED** |
| **SEC-12** | `TestSEC12_ScratchOrphanCleanup` | **V-11** | Cryptographic `mkdtemp` (0700) and scavenger purge of abandoned dirs > 24h. | **PASSED** |
| **SEC-13** | `TestSEC13_CacheStagingAndSync` | **V-12** | Read-only host cache mounts with ephemeral staging and verified sync-back. | **PASSED** |
| **SEC-14** | `TestSEC14_NestedAirlockBypass` | — | `__AIRLOCK_ACTIVE=1` recursion bypass for nested toolchain invocations. | **PASSED** |
| **SEC-15** | `TestSEC15_DNSTunnelingNeutralization` | **V-08** | In-process RFC 1035 UDP DNS forwarder returning `NXDOMAIN` on non-whitelisted domains. | **PASSED** |
| **SEC-16** | `TestSEC16_AuditLogging` | — | Structured JSON-lines audit logging to `~/.airlock/audit.log` (0600 permissions). | **PASSED** |
| **SEC-17** | `TestSEC17_ShimRecursionPrevention` | **V-14** | Transparent shell shims execution without recursion crashes. | **PASSED** |
| **SEC-18** | `TestSEC18_ArgusStaticAnalysisHandoff` | — | Argus heuristic analysis and external `vetpkg` binary handoff. | **PASSED** |
| **SEC-19** | `TestSEC19_TyposquattingInterception` | — | Pre-execution interception of known typosquats (`crossenv`, `reqeusts`). | **PASSED** |
| **SEC-20** | `TestSEC20_RustBuildRsNetworkInterception`| — | Argus detection of outbound network sockets inside Rust `build.rs`. | **PASSED** |
| **SEC-21** | `TestSEC21_SetupPyObfuscationInterception`| — | Interception of obfuscated base64 and reverse shell payloads in Python `setup.py`. | **PASSED** |
| **SEC-22** | `TestSEC22_DeclarativeConfigDomainAllow` | — | Declarative `airlock.yaml` custom domain and wildcard allowlists. | **PASSED** |
| **SEC-23** | `TestSEC23_DeclarativeConfigGuardrailDenial`| — | Guardrail rejection preventing `airlock.yaml` from overriding zero-trust boundaries. | **PASSED** |
| **SEC-24** | `TestSEC24_InteractiveCapabilityGrantPrompt`| — | Dynamic interactive terminal prompts for unknown network domains. | **PASSED** |
| **SEC-25** | `TestSEC25_ConfigInitAndValidation` | — | Policy scaffolding (`airlock init`) and validation against guardrails. | **PASSED** |
| **SEC-26** | `TestSEC26_MCPSandboxConfinement` | — | Verifying MCP `airlock_exec` executes strictly inside zero-trust kernel sandbox. | **PASSED** |
| **SEC-27** | `TestSEC27_MCPVetAndPolicyCheck` | — | MCP `airlock_vet` and `airlock_policy_check` tool threat detection and guardrails. | **PASSED** |
| **SEC-28** | `TestSEC28_DoctorHealthyEnvironment` | — | `airlock doctor` diagnostic suite verifying platform, shims, and scratch health. | **PASSED** |
| **SEC-29** | `TestSEC29_AuditQueryCapturesThreats` | — | `airlock audit` query engine indexing blocked egress, DNS tunneling, and CSV export. | **PASSED** |
| **SEC-30** | `TestSEC30_MCPExtensions` | — | MCP protocol compliance for resources (`audit`, `policy`, `health`) and prompts. | **PASSED** |
| **SEC-31** | `TestSEC31_ExtendedSupplyChainThreats` | — | Argus static analysis detection across Go, Ruby, and Obfuscated Shell pipelines. | **PASSED** |

---

## 🧪 Verification & Testing

```bash
# Run unit and integration tests
make test

# Run micro-benchmark harness
go test -v -bench=. ./tests/benchmark_test.go

# Run full 31/31 Adversarial Security Suite
go test -v ./tests/...

# Cross-compile for all supported architectures (macOS arm64/amd64, Linux arm64/amd64)
make cross-compile
```

---

## 📄 License

MIT License — Copyright (c) 2026 Ben Skolmoski. See [LICENSE](LICENSE) for details.
