# Gemini CLI Integration with Airlock MCP ♊

Integrate Google Gemini CLI and agent loops with Airlock to provide autonomous agent confinement, pre-execution static analysis, and real-time security auditing.

---

## 🚀 Setup Instructions

### 1. Global MCP Configuration

Add the Airlock server definition to your Gemini CLI MCP configuration in `~/.gemini/antigravity-cli/mcp_config.json`:

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

Alternatively, use the standalone binary:

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

### 2. Verify Server Status

Test that Gemini CLI can communicate with Airlock:

```bash
# Verify the MCP server starts cleanly
airlock mcp
```

---

## 🛡️ Agent Tool Invocations

When Gemini CLI needs to execute shell commands, build code, or install third-party dependencies:

1. **Vetting First**: Calls `airlock_vet` with the proposed command to check for typosquats or supply-chain trojans.
2. **Confined Execution**: Calls `airlock_exec` with `workspace` set to the project root and `airgap: true` (or domain allowlists).
3. **Policy Checking**: Calls `airlock_policy_check` to ensure paths and environment variables comply with `airlock.yaml`.
