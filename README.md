# Airlock

> **Minimalist Workstation Sandbox for Untrusted Package Installs & Agentic Loops**

Airlock (`boxpkg`) provides instant-startup, zero-VM process confinement for package manager installations and untrusted code execution.

---

## 1. Executive Summary & Problem Statement

Modern package managers execute arbitrary code at install time (`postinstall` hooks in npm, `setup.py` / wheels in pip, `build.rs` in cargo). 

Standard terminal runs give these scripts unconfined read access to host credentials (`~/.ssh`, `~/.aws`, `~/.gnupg`), macOS Keychain daemons, and outbound network sockets. Airlock provides transparent, sub-second confinement directly on the workstation without the overhead of heavy virtual machines or containers.

---

## 2. Confinement Specifications

* **Filesystem Confinement:** Only `$PWD` (current workspace) and an isolated scratch directory (`/tmp/boxpkg-<pid>`) are writable. Secrets and host configuration dotfiles are strictly blocked.
* **Keychain & Secrets Isolation:** Denies Mach IPC lookups to security/keychain daemons on macOS.
* **Environment Sanitization:** Automatically strips sensitive environment variables matching `*TOKEN*`, `*KEY*`, `AWS_*`, and common API credentials before launching scripts.
* **Network Egress Modes:** Supports offline airgap (`--airgap`) or restricted HTTPS egress to verified package registries only.

---

## 3. Isolation Matrix

| Target Resource | Permission | Rationale & Implementation |
| :--- | :---: | :--- |
| **`$PWD` (Workspace)** | **Read-Write** | Package managers must write `node_modules`, lockfiles, build artifacts. |
| **`/tmp/boxpkg-<pid>`** | **Read-Write** | Ephemeral scratch directory for intermediate compiler objects. |
| **`~/.ssh`, `~/.aws`, `~/.gnupg`** | **BLOCKED (DENY)** | Complete denial of host secrets harvesting. |
| **macOS Keychain / Daemons** | **BLOCKED (DENY)** | Deny Mach service lookups to security agents and credential stores. |
| **Toolchains (`/usr`, `/bin`, `/lib`)** | **Read-Only** | Compilers and runtimes execute without modification rights. |
| **Outbound Network** | **Restricted** | Only known package registry HTTPS endpoints permitted. |

---

## 4. Implementation Roadmap (8 Weeks)

* **Phase 1 (Weeks 1–3):** macOS Seatbelt profile synthesis (`sandbox-exec`), environment stripper.
* **Phase 2 (Weeks 4–6):** Linux engine using unprivileged namespaces + Bubblewrap / Landlock LSM.
* **Phase 3 (Weeks 7–8):** Registry-proxy egress filter, IDE integrations, and automated `vetpkg` (Argus) handoff.

---

## Project Specification

Detailed PDF specification available in [project_plan.pdf](project_plan.pdf).
