# Antigravity Agent Rule: Airlock Workstation Sandboxing

## Policy Directives for AI Agents

When executing shell commands or modifying codebase dependencies:

1. **Untrusted Package Installations**:
   - All package installation and dependency management commands (`npm install`, `pnpm add`, `yarn add`, `pip install`, `cargo add`, `uv pip install`, `bun add`) MUST run through `airlock` or transparent shims (`~/.airlock/bin`).
   - If invoking directly: `airlock run -- <package_manager> <args...>` or `airlock <package_manager> <args...>`.

2. **Pre-Execution Static Analysis (Argus / Vet)**:
   - When introducing new third-party dependencies from unvetted sources, use `--vet` or `--vet-strict` to inspect manifests and detect typosquats:
     `airlock --vet npm install <package>`

3. **Workspace Integrity Protection**:
   - Airlock automatically restricts write access to the workspace `$PWD` and temporary scratch spaces, blocking access to `~/.ssh`, `~/.aws`, `~/.gnupg`, macOS Keychain, and `/var/run/docker.sock`.
   - Denies write modifications to `.git` hooks.
   - Denies read access to workspace secret files (`.env*`, `*.pem`, `*.key`).

4. **Non-Interactive Loops**:
   - In autonomous headless loops, pass `--non-interactive` to ensure standard I/O pipes operate cleanly without PTY allocation prompts.
