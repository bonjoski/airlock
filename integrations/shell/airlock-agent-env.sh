#!/usr/bin/env bash
# Airlock AI Agent Environment Initializer
# Source this file in autonomous agent startup scripts (Claude Code, Cursor, Codex, Antigravity, OpenHands, Aider)
# Usage: source ~/.airlock/integrations/shell/airlock-agent-env.sh

# 1. Prioritize Airlock shims in PATH
if [ -d "$HOME/.airlock/bin" ]; then
    export PATH="$HOME/.airlock/bin:$PATH"
fi

# 2. Inform subshells of Airlock agent mode
export AIRLOCK_AGENT_MODE=1

# 3. Pre-execution static analysis default for autonomous agent loops
export AIRLOCK_VET_STRICT=1

# 4. Helper function to execute arbitrary commands inside Airlock sandbox
airlock_exec() {
    if command -v airlock >/dev/null 2>&1; then
        airlock run --non-interactive -- "$@"
    else
        "$@"
    fi
}

# 5. Helper function for airgap offline executions
airlock_airgap() {
    if command -v airlock >/dev/null 2>&1; then
        airlock run --airgap --non-interactive -- "$@"
    else
        "$@"
    fi
}
