# Airlock 🛡️

> **Minimalist Zero-Trust Workstation Sandbox for Untrusted Package Installs & Autonomous AI Coding Loops**

[![CI](https://github.com/bonjoski/airlock/actions/workflows/ci.yml/badge.svg)](https://github.com/bonjoski/airlock/actions/workflows/ci.yml)
[![Release](https://img.shields.io/github/v/release/bonjoski/airlock?color=blue)](https://github.com/bonjoski/airlock/releases)
[![License: MIT](https://img.shields.io/badge/License-MIT-green.svg)](https://opensource.org/licenses/MIT)

Airlock (`airlock`, aliased as `boxpkg`) provides sub-15ms, zero-VM process confinement for package manager installations (`npm`, `pip`, `cargo`, `uv`, `bun`, `pnpm`, `yarn`) and AI-generated script execution directly on developer workstations.

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

## ⚡ Key Features

* **Sub-15ms Startup Overhead:** Zero daemons, zero VMs, zero Docker containers.
* **macOS Confinement Engine:** Native Apple Seatbelt sandbox with runtime dynamic scheme compilation and Mach IPC service lookup denials.
* **Linux Container Engine:** Unprivileged user namespace isolation via Bubblewrap (`bwrap`) paired with custom Seccomp-BPF filters blocking `io_uring`, `ptrace`, and `TIOCSTI` terminal injection.
* **Egress DNS & Proxy Shield:** In-process RFC 1035 UDP DNS forwarder and HTTPS forward proxy blocking DNS tunneling data exfiltration (`NXDOMAIN` on non-allowlisted domains).
* **Transparent Toolchain Shims:** Automatic shimming for `npm`, `npx`, `pnpm`, `yarn`, `pip`, `pip3`, `cargo`, `uv`, and `bun` with recursion bypass.
* **Argus Static Analysis Handoff:** Pre-execution heuristic scanner inspecting suspicious command patterns (`curl | sh`) and package lifecycle hooks.
* **Declarative Project Policies (`airlock.yaml`):** Per-repository Policy-as-Code with strict guardrails and wildcard domain matching.
* **Dynamic Interactive Capability Grants:** Real-time terminal prompts when unlisted domains are requested (`Allow once`, `Allow session`, `Save to airlock.yaml`).
* **Structured Audit Logging:** Non-blocking JSON-lines security telemetry logged to `~/.airlock/audit.log`.

---

## 🛠️ Usage & CLI Reference

### Run Commands in Sandbox
```bash
# Explicit run syntax
airlock run -- npm install

# Direct shorthand syntax
airlock npm install
airlock pip install -r requirements.txt
airlock cargo build
```

### Declarative Project Policies (`airlock.yaml`)
Scaffold, configure, and validate repository-level sandbox policies:
```bash
# Initialize a policy tailored to your project type (node, python, rust, go, general)
airlock init --type node

# Validate an existing policy against security invariant guardrails
airlock config validate
```

Example `airlock.yaml`:
```yaml
version: "1"
mode: strict

network:
  airgap: false
  allow_domains:
    - "api.github.com"
    - "*.internal.corp"
  unknown_domain_action: prompt

env:
  allow:
    - "NODE_ENV"
    - "NPM_CONFIG_REGISTRY"
  deny:
    - "DATABASE_URL"

filesystem:
  allow_read: []
  allow_write: []
  deny_read: []

vetting:
  enable: true
  strict: false
  ignored_rules: []

interactive:
  prompt_on_unknown_domain: true
  prompt_timeout_sec: 15
```

### Offline Airgap Isolation
Block all outbound network connections:
```bash
airlock --airgap npm install
```

### Allow Additional Registry Domains
```bash
airlock --allow-domain internal.artifactory.company.com npm install
```

### Manage Transparent Package Manager Shims
Install shell shims in `~/.airlock/bin` so that running `npm`, `pip`, or `cargo` in your terminal automatically executes inside Airlock:
```bash
# Install transparent shims
airlock shim install

# Check status of installed shims
airlock shim list

# Remove shims
airlock shim uninstall
```

### Pre-Execution Static Analysis (`--vet` / Argus)
```bash
# Scan command line and workspace manifests before sandbox entry
airlock --vet npm install

# Fail-closed on High or Critical severity findings
airlock --vet-strict npm install
```

---

## 🛡️ Security Confinement Matrix

| Target Resource | Confinement Level | Enforcement Mechanism |
| :--- | :---: | :--- |
| **Workspace (`$PWD`)** | **Read-Write** | Permitted for build artifacts & `node_modules` (writes to `.git` denied). |
| **Host Secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`)** | **BLOCKED** | Absolute path Seatbelt rules (macOS) & mount masking (Linux). |
| **Workspace Secrets (`.env`, `*.pem`)** | **BLOCKED** | Per-workspace secret scanning & filesystem read denials. |
| **Keychain & Security IPC** | **BLOCKED** | Denies Mach lookup to `securityd`, `launchservicesd`, `pasteboard`. |
| **Outbound Network Sockets** | **Restricted** | Ephemeral egress proxy & in-process RFC 1035 DNS filter with wildcard matching. |
| **System Calls (`io_uring`, `ptrace`, `TIOCSTI`)**| **BLOCKED** | Pure-Go compiled Seccomp-BPF filter. |
| **Host Caches (`~/.npm`, `~/.cache/pip`, etc.)** | **Read-Only / Ephemeral**| Read-only mount + isolated staging scratch + atomic verified sync-back. |
| **Policy Invariants** | **Guaranteed** | Declarative policies (`airlock.yaml`) cannot weaken root zero-trust boundaries. |

---

## 🧪 Verification & Development

```bash
# Run unit and integration tests
make test

# Run Go race condition tests
make test-race

# Run 25/25 Adversarial Security Verification Suite
make test-sec

# Run installer script test suite
make test-install

# Cross-compile for all supported architectures
make cross-compile

# Package release archives with sha256 checksums
make package
```

---

## 📄 License

MIT License — Copyright (c) 2026 Ben Skolmoski. See [LICENSE](LICENSE) for details.
