# ADR-0001: Sub-15ms Kernel Sandboxing via macOS Seatbelt & Linux Landlock

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/sandbox`, `cmd/airlock`
- **Deciders:** Lead Systems Architect & Kernel Sandbox Engineer

---

## 1. Context & Problem Statement

AI coding agents and developer build tools frequently run untrusted third-party code and scripts.
- Docker and microVMs provide strong isolation but add 500ms – 2,000ms startup latencies, making them too slow for rapid command-line loops (`git status`, `npm test`, `cargo check`).
- Standard developer processes have full ambient access to user home directories and credentials.

---

## 2. Decision Outcome

We built **Airlock**, a Tier 1 kernel sandbox executing with **< 15ms latency** using native OS kernel primitives:

1. **macOS Apple Seatbelt (`sandbox-exec` / `libsandbox`):**
   - Compiles Scheme profiles restricting filesystem read/write to the active workspace directory and blocking WAN network socket creation.
2. **Linux Landlock LSM & Seccomp-BPF:**
   - Drops ambient process rights, restricts directory access to workspace roots, and blocks dangerous system calls (`ptrace`, `kexec_load`).
3. **Pure In-Process Execution:**
   - Jails apply directly at process launch (~7.9ms startup) with zero daemon proxy overhead.

---

## 3. Consequences

- **Positive:** Sub-10ms startup; zero container engine dependencies; protects host credentials against malicious build scripts.
- **Negative:** Kernel sandboxing does not provide full OS kernel separation against kernel 0-day exploits (Tier 2 microVMs like Aegisbox handle untrusted binary execution).
