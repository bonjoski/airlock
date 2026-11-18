# Airlock Architectural Decision Records (ADRs)

This directory documents the key architectural decisions, kernel sandbox invariants, and operating system primitives governing [`bonjoski/airlock`](https://github.com/bonjoski/airlock).

## ADR Index

| ADR ID | Title | Status | Date | Scope |
| :--- | :--- | :--- | :--- | :--- |
| **[ADR-0001](0001-sub-15ms-kernel-sandboxing-seatbelt-landlock.md)** | **Sub-15ms Kernel Sandboxing via macOS Seatbelt & Linux Landlock** | `Accepted` | 2026-10-30 | `pkg/sandbox`, `cmd/airlock` |
| **[ADR-0002](0002-trojanized-developer-agent-confinement.md)** | **Trojanized Developer Agent & Extension Confinement** | `Accepted` | 2026-10-30 | `pkg/policy`, `pkg/security` |

---

## Architectural Principles

1. **Kernel-Enforced Isolation:** Enforces least-privilege filesystem and network isolation directly via native OS kernel mechanisms (macOS Seatbelt/`sandbox-exec`, Linux Landlock LSM, seccomp-bpf).
2. **Sub-15ms Latency SLA:** Zero daemon overhead and zero container startup delay; sandboxing applies in-process at `execve` time in `< 10ms`.
3. **Fail-Closed Filesystem Boundary:** Strict deny-by-default on private credential paths (`~/.ssh`, `~/.aws`, `~/.gnupg`, macOS Keychain).
