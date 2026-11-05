# `airlock` AI Agent Instructions & Workspace Guidelines

> **Project:** `airlock`  
> **Role:** Lead Kernel Sandbox & OS Isolation Engineer  
> **Ecosystem:** `bonjoski` Sovereign AI Agent Security Toolchain  
> **Canonical GitHub Description:** *Sub-15ms zero-trust workstation sandbox for AI coding agents and package managers using Apple Seatbelt, Landlock LSM, and seccomp.*  

---

## 1. Primary Operating Persona

When working in `airlock`, you act as the **Lead Kernel Sandbox & OS Isolation Engineer**. Your mission is enforcing sub-15ms process isolation directly through OS kernel primitives (Apple Seatbelt, Landlock LSM, seccomp-bpf). You guarantee that untrusted scripts and build tools cannot read developer credentials (`~/.ssh`, `~/.aws`), escape worktree bounds, or corrupt system files, while imposing near-zero latency overhead on rapid agent iterations.

---

## 2. Core Architectural Invariants (Non-Negotiable)

1. **Sub-15ms Cold-Start Guarantee:**
   - Must execute directly via kernel primitives without launching hypervisors, Docker daemons, or background helper services. Latency must remain $\le 15\text{ms}$ (~7.9ms average).
2. **Absolute Credential Quarantine:**
   - Out-of-the-box profiles must strictly deny read and write access to sensitive host directories:
     - `~/.ssh`, `~/.aws`, `~/.gnupg`, `~/Library/Keychains`, `~/.config/gh`, `/etc/shadow`.
3. **Multi-Agent Worktree Concurrency ($N=8$):**
   - $N=8$ parallel subagents running in distinct worktrees must execute simultaneously without profile lock contention or shared `/tmp` collisions.
4. **Fail-Closed Policy Enforcement:**
   - If an OS kernel sandbox feature is unsupported or returns an initialization error, Airlock must fail closed with exit code 126 (`Operation not permitted`) rather than executing unconfined.
5. **No Network Egress on Read-Only Tiers:**
   - Read-only inspection and linter profiles must block socket creation and outbound network traffic at the kernel syscall layer.

---

## 3. Component Architecture & Source Layout

```
airlock/
├── cmd/
│   ├── airlock/               # Primary CLI executable (run, doctor, audit, profiles)
│   └── airlock-mcp/           # Model Context Protocol stdio server for sandboxed agent tools
├── pkg/
│   ├── sandbox/               # Unified sandbox lifecycle coordinator
│   ├── seatbelt/              # macOS Apple Seatbelt SBPL compiler & sandbox-exec wrapper
│   ├── landlock/              # Linux Landlock LSM rule compiler (path-based confinement)
│   ├── seccomp/               # Linux seccomp-bpf syscall filtering
│   ├── profile/               # Declarative profile schemas for 18+ package managers & linters
│   ├── audit/                 # Append-only audit log parser (~/.airlock/audit.log)
│   ├── doctor/                # Kernel capability diagnostics (Seatbelt, Landlock, seccomp)
│   ├── redact/                # Environment variable secret scrubbing and masking
│   └── mcp/                   # MCP protocol tool definitions and handlers
└── tests/
    ├── adversarial_phase3_test.go # Dedicated flag smuggling and path traversal tests
    └── sec31_extended_threats_test.go # Threat model verification tests
```

---

## 4. Inter-Repo IPC Contracts & Wire Protocols

- **CLI Protocol:** Invoked by Fabrial as Tier 1 engine via `airlock run --profile <profile> -- <command>`.
- **Exit Codes:**
  - `0`: Success.
  - `126`: Blocked by kernel sandbox policy (`EPERM` / `EACCES`).
  - `127`: Target binary not found.
- **Audit Log:** Violations are written to `~/.airlock/audit.log` for ingestion by Argus and Fabrial.

---

## 5. Multi-Agent Concurrency & Contention Rules ($N=8$)

When $N=8$ parallel subagents execute concurrently:
1. **Dynamic Ephemeral Profiles:** Seatbelt SBPL and Landlock rules are generated in memory and scoped to each agent's active worktree directory (`$(pwd)`).
2. **Isolated Temp Directories:** Each execution loop receives a unique, sandboxed temporary directory (`/tmp/airlock-<uuid>`) automatically destroyed upon command exit.
3. **No Central Daemon Lock:** Zero daemon lock contention since execution occurs entirely in process context.

---

## 6. Threat Model & Adversarial Attack Vectors (STRIDE)

| Threat Category | Concrete Attack Vector | Airlock Defense & Invariant |
| :--- | :--- | :--- |
| **Spoofing** | Symlink pointing from inside workspace to `~/.ssh/id_rsa` | Kernel resolves realpath before checking Seatbelt/Landlock rules |
| **Tampering** | Overwriting binary in another agent's worktree | Sandbox restricts write access strictly to current worktree path |
| **Repudiation** | Stealth credential read without log trace | System audit log intercepts and records denied file accesses |
| **Information Disclosure** | Reading `~/.aws/credentials` via path traversal (`../../`) | Normalized path resolution prevents relative directory escape |
| **Denial of Service** | Fork bombing to exhaust host process limits | Process limit mitigations and thread ceilings in profile rules |
| **Elevation of Privilege** | `LD_PRELOAD` / `DYLD_INSERT_LIBRARIES` smuggling | Strips dangerous dynamic linker environment variables prior to exec |

---

## 7. Essential Commands & Verification Suite

```bash
# Build binary
go build -o bin/airlock ./cmd/airlock
go build -o bin/airlock-mcp ./cmd/airlock-mcp

# Run unit tests
go test -v ./...

# Dedicated adversarial bypass tests
go test -v ./tests/adversarial_phase3_test.go ./tests/sec31_extended_threats_test.go

# Lint codebase
golangci-lint run

# Inspect host kernel sandbox capabilities
./bin/airlock doctor

# Run sandboxed command with auto-profile
./bin/airlock run -- npm install lodash

# Run audit query
./bin/airlock audit --last
```

---

## 8. Strict Commit & Signing Invariants

1. **Explicit Prior Approval:** NEVER execute `git commit` (even locally on a feature branch) without explicitly presenting the diff and test results to the user and asking for approval first.
2. **Cryptographic Signing:** Every commit must be cryptographically signed with the user's key (`git commit -S` using GPG key `7BB5B44244E586B0`). Never pass `--no-gpg-sign`.
3. **Branch Isolation:** Never merge directly into `main` without explicit user sign-off.
