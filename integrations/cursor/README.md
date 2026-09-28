# Cursor IDE Integration with Airlock MCP ⚡

Confine Cursor Composer and Agent background execution inside the Airlock zero-trust sandbox to prevent malicious package scripts or hallucinated shell loops from leaking SSH credentials, tampering with `.git` hooks, or escaping to root sockets.

---

## 🚀 Setup Instructions

### Option 1: Workspace-Level Configuration (Recommended)

1. Create a `.cursor/mcp.json` file in your project root.
2. Copy the contents of [`cursor_mcp.json`](cursor_mcp.json):

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

### Option 2: Global Cursor Settings

1. Open **Cursor Settings** (`Cmd + ,` on macOS, `Ctrl + ,` on Linux/Windows).
2. Navigate to **Features** > **MCP Servers**.
3. Click **Add New MCP Server**:
   - **Name**: `airlock`
   - **Type**: `stdio`
   - **Command**: `airlock mcp` (or full path `/usr/local/bin/airlock mcp`)

---

## 💡 How Cursor Uses Airlock

* When Cursor's Agent attempts to install dependencies (`npm install`, `pip install`, `cargo add`), it invokes `airlock_exec` or `airlock_vet` to sandbox the process.
* Host secrets (`~/.ssh`, `~/.aws`, `~/.gnupg`) and `.git` hooks are completely hidden and write-protected.
* Any unauthorized outbound connection (e.g. to a remote C2 server) is blocked by the fail-closed egress proxy with immediate audit telemetry.
