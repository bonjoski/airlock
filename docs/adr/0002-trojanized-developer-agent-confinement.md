# ADR-0002: Trojanized Developer Agent & Extension Confinement

- **Status:** Accepted
- **Date:** 2026-10-30
- **Component:** `pkg/policy`, `pkg/security`
- **Deciders:** Lead Systems Architect & Kernel Sandbox Engineer

---

## 1. Context & Problem Statement

VS Code extensions, MCP servers, and autonomous agents downloaded from open registries can contain trojanized dependencies that attempt to read developer credentials or open reverse shells during execution.
- Existing developer environments execute IDE extensions with full user privileges.

---

## 2. Decision Outcome

We created dedicated **Extension & Agent Confinement Profiles** in Airlock:

1. **Deny-by-Default Credential Isolation:**
   - Blacklists all sensitive dotfiles (`~/.ssh`, `~/.aws`, `~/.kube`, `~/.gnupg`, `~/.config/gcloud`).
2. **Read-Only System Libraries:**
   - Mounts system headers and toolchains as read-only; denies writing to `/usr`, `/opt`, or system binary locations.
3. **Workspace-Scoped Temporary Overlay:**
   - Scopes write capabilities strictly to `./` and `/tmp/airlock-<session>`.

---

## 3. Consequences

- **Positive:** Malicious npm packages, post-install hooks, and trojanized agents cannot harvest host credentials.
- **Negative:** Build tools attempting to write outside the workspace (e.g. global cache writes to `~/.cache`) require explicit path declarations in `airlock.yaml`.
