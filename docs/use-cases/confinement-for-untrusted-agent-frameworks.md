# 🛡️ Confinement for Untrusted Agent Frameworks (`--profile untrusted-agent`)

> **Use Case:** Safely evaluate and run third-party local AI agent frameworks (`uvx`, `pipx`, `npx`) without exposing host SSH keys, shell startup files, cloud credentials, or unrestricted network egress.  
> **Engine:** macOS Seatbelt SBPL / Linux Landlock LSM + Bubblewrap + Seccomp-BPF  
> **Startup Overhead:** `<15ms` (Zero-VM, Zero-Daemon)  

---

## 🛑 The Threat Model

Fast-moving third-party agent frameworks and MCP tools often require broad local shell execution while expecting cloud or LLM API credentials in `os.environ`. Running them unconfined on a developer workstation exposes:

1. **Ambient Credential Harvesting:** Reading `AWS_*`, `ANTHROPIC_API_KEY`, `OPENAI_API_KEY`, `GITHUB_TOKEN`, or `SSH_AUTH_SOCK` directly from process memory and exfiltrating them to tunneling domains (`ngrok`, `trycloudflare`).
2. **Persistence Backdoors:** Appending attacker keys to `~/.ssh/authorized_keys`, tampering with `~/.bashrc`, `~/.zshrc`, `~/.profile`, planting macOS `~/Library/LaunchAgents`, or writing `/etc/cron*` entries.
3. **`PATH` Binary Shadowing & Linker Hijacking:** Dropping fake `git`, `ssh`, or `curl` wrappers into `./bin` or `~/.local/bin`, or smuggling `LD_PRELOAD`, `DYLD_INSERT_LIBRARIES`, `PYTHONPATH`, or `NODE_OPTIONS`.
4. **Loopback & Metadata SSRF:** Probing local control planes (`127.0.0.1:8080`, `11434`, `2375`) or cloud metadata endpoints (`169.254.169.254`).

---

## 🚀 Quickstart Recipes

### 1. Strict Offline Execution (`WAN=DENY` by Default)

With zero egress flags, `--profile untrusted-agent` enforces `WAN=DENY`, pins `PATH` to immutable system directories (`/usr/bin:/bin:/opt/homebrew/bin`), scrubs all ambient cloud/LLM/linker environment variables, and denies read/write access to `~/.ssh`, `~/.ssh/authorized_keys`, `~/.bashrc`, `~/.zshrc`, `~/.profile`, `~/Library/LaunchAgents`, `/etc/cron*`, `~/.aws`, and `/var/run/docker.sock`:

```bash
airlock run --profile untrusted-agent -- python3 agent_eval.py
```

### 2. Declared-API-Only Egress (`--allow-egress`)

Permit outbound HTTPS traffic exclusively to explicitly declared public LLM API hostnames while rejecting wildcards (`*`), RFC 1918 private IPs, loopback targets, and cloud IMDS (`169.254.169.254`) fail-closed:

```bash
# 1. Pre-flight check package and workspace policy before launching
argus vet pip install <agent-framework>
airlock vet --strict --dir .

# 2. Launch third-party agent runtime strictly confined to declared API hosts
airlock run --profile untrusted-agent \
  --allow-egress api.anthropic.com,api.openai.com \
  -- uvx <agent-framework>
```

### 3. Local Loopback Keyless Proxy Mode (`--keyless-proxy`)

When a third-party framework demands an API key in `os.environ` (such as `ANTHROPIC_API_KEY`), route outbound API calls through a local loopback keyless proxy (`127.0.0.1:<port>` or `[::1]:<port>`) that injects real short-lived credentials only for declared upstream hosts. Even if the framework dumps `os.environ`, real keys never exist inside the sandbox:

```bash
airlock run --profile untrusted-agent \
  --keyless-proxy 127.0.0.1:8443 \
  -- uvx <agent-framework>
```

`--keyless-proxy` strictly validates canonical loopback IP literals (`127.0.0.1:<port>` or `[::1]:<port>`) using `netip.ParseAddrPort` and fails closed on hostnames, remote IPs, or non-loopback addresses.

---

## 🔍 Pre-Flight Hard-Boundary Linting (`airlock vet --strict`)

Before running an untrusted agent inside a repository with a custom `.airlock.yaml`, verify that the compiled kernel policy contains zero Siren misconfiguration anti-patterns (broad reads without credential denies, missing `~/.ssh`/`~/.aws`/`docker.sock` blocks, wildcard egress, relative `PATH`, disabled seccomp `io_uring`/x32 guards, or fail-open modes):

```bash
# Lint workspace config & compiled sandbox profile (exits 30 on findings)
airlock vet --strict --dir .

# Machine-readable JSON output for CI/CD gates
airlock vet --strict --dir . --json

# Expand full finding details with progressive disclosure
airlock vet --strict --dir . --why
```

---

## ✅ Verification Checklist

Confirm confinement guarantees in under 1 second:

```bash
# 1. Confirm immutable PATH and stripped ambient secrets
AWS_SECRET_ACCESS_KEY=dummy ANTHROPIC_API_KEY=dummy PATH="./bin:$PATH" \
  airlock run --profile untrusted-agent -- /usr/bin/env

# 2. Confirm ~/.ssh/authorized_keys write is denied at the OS kernel layer
airlock run --profile untrusted-agent -- /bin/sh -c 'echo test >> "$HOME/.ssh/authorized_keys"'

# 3. Confirm wildcard & IMDS egress flags fail closed
airlock run --profile untrusted-agent --allow-egress '*' -- /usr/bin/true
airlock run --profile untrusted-agent --allow-egress 169.254.169.254 -- /usr/bin/true

# 4. Confirm non-loopback keyless proxy fails closed
airlock run --profile untrusted-agent --keyless-proxy 10.0.0.5:8443 -- /usr/bin/true
```
