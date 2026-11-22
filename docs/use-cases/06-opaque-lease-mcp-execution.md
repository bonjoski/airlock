# Use Case 06: Opaque-Lease Sandboxed Execution & `BLPR-v1` Receipts (`UB-MCP-v1`)

> **Goal:** Execute agent-driven tests that need ephemeral credentials inside Airlock's `<10ms` kernel sandbox while blocking stdout secret exfiltration and emitting verifiable `BLPR-v1` local receipts.

## Workflow
1. **Obtain an opaque handle from Locksmith (`locksmith_checkout_lease`)** — returns `lease_...` with zero raw secret bytes.
2. **Execute via `airlock_exec` MCP tool with `secret_leases` & `session_id`:**
   ```json
   {
     "command": "go",
     "args": ["test", "./billing/..."],
     "workspace": "/path/to/repo",
     "secret_leases": ["lease_9f8a7b6c..."],
     "session_id": "sess_01JDX9J00...",
     "emit_receipt": true
   }
   ```
3. **What Airlock Enforces Automatically:**
   * Redeems `lease_...` directly over `LOCKSMITH_SOCKET` (`action: "redeem_opaque_lease"`), verifying `session_id` and single-use binding.
   * Zeroizes the secret byte slice immediately after injection (`defer clear(secretBytes)`).
   * Scans child `stdout`/`stderr` (both literal and base64 forms) and **fails closed** with `AIRLOCK_SECRET_LEAK_BLOCKED` (`exit_code: 40`, `UB-MCP-v1` `structuredContent`) if any leased secret leaks.
   * Atomically writes a signed DSSE / in-toto Statement v1 receipt (`0600`, `os.OpenRoot`, `O_NOFOLLOW`) to `FABRIAL_RECEIPT_DIR` verifiable via `fabrial receipt verify`.
