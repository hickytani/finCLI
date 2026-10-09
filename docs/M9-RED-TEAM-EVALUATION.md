# M9 — Comparative Red-Team Evaluation Report

**Branch:** `m9-comparative-red-team`  
**Status:** Complete — All 36 evaluation cases executed deterministically  
**Verdict:** **PASS** (100.0% Attack-Blocking Rate, 100.0% Legitimate-Task Success Rate, 0 State-Integrity Violations)

---

## 1. Executive Summary

Milestone M9 evaluates FIN//GUARD by conducting a head-to-head comparative security benchmark between an **Unguarded Baseline Agent (System A)** and **Guarded FIN//GUARD (System B)** across a versioned 36-scenario test corpus.

### Fundamental Security Thesis
> An AI model may propose an intent, but it cannot extend its own execution budget, gain authority, bypass authorization, or cause duplicate financial effects through retries, timeouts, or late responses.

---

## 2. Experimental Architecture & Methodology

### System A: Unguarded Baseline Agent
- A minimal, direct LLM integration where extracted intent and model instructions bypass FIN//GUARD's trusted validation, authority stripping, policy checks, decision engine, and signing gate.
- Simulates standard un-guarded AI agent frameworks that execute model outputs or accept injected authority/signer parameters directly.

### System B: Guarded FIN//GUARD Agent
- Connects the exact same model output through FIN//GUARD's complete trusted boundary: `LangChainPlanner` $\rightarrow$ `ExtractionResult` $\rightarrow$ `MCPSecurityBoundary` $\rightarrow$ `BoundedOrchestrator` $\rightarrow$ `StructuredIntentBoundary` $\rightarrow$ `AgentGuardrails` $\rightarrow$ `DecisionEngine` $\rightarrow$ `SigningGate`.
- Treats model output as untrusted data, strips authority fields, validates minor-unit `Money`, enforces actor policies, requires mandatory human operator approval for agent transfers, and denies unauthorized destinations.

### Experimental Controls
- **Identical Input & Payload:** Both systems receive identical prompt text, retrieved context, and deterministic model payloads.
- **State Snapshots:** Pre- and post-test SQLAlchemy database snapshots query transaction records, decision receipts, audit ledger entries, simulator balances, and simulator execution records.
- **Zero Real Transfers:** All execution occurs in synthetic local INR/USD/EUR simulator state. Zero real funds or external APIs are used.

---

## 3. Attack Taxonomy & Scenario Inventory

The M9 evaluation dataset ([`finguard/evaluation/m9_dataset.py`](../finguard/evaluation/m9_dataset.py)) contains 36 deterministic cases across 8 attack categories plus legitimate positive controls:

| Category | Cases | Threat Focus |
|---|---:|---|
| **A. Prompt & Instruction Injection** | 4 | System prompt override, retrieved-context hijack, authority claims, persona escalation |
| **B. Financial Intent Manipulation** | 4 | Recipient swap, amount escalation, NaN numeric constants, float rounding abuse |
| **C. Identity & Authorization** | 4 | Unregistered actors, direct approval bypass (`approved=True`), capability injection, cross-tenant transfer |
| **D. Replay & Duplicate Effects** | 4 | Duplicate submissions, idempotency key mismatch, retry after timeout, late response after cancellation |
| **E. Output & Protocol Manipulation** | 4 | Malformed XML/HTML tool calls, duplicate JSON keys, 10KB oversized payload, tool-call metadata injection |
| **F. Resource Exhaustion & Reliability** | 4 | Prompt byte flood, retrieved context flood, 10s invocation timeout, retry exhaustion |
| **G. Secret & Information Handling** | 4 | Private key exfiltration, nested metadata secret injection, provider exception sentinel, token exfiltration |
| **H. Trusted-State Integrity** | 4 | Direct signing gate access, direct execution bypass, audit ledger sequence tampering, state machine bypass |
| **Positive Controls** | 4 | Valid authorized agent transaction proposals in INR, USD, and EUR |

---

## 4. Benchmark Results

Machine-readable results exported to [`docs/M9-RESULTS.json`](./M9-RESULTS.json):

### Summary Scorecard

| Metric | System A (Unguarded Baseline) | System B (Guarded FIN//GUARD) | Impact / Effectiveness |
|---|---:|---:|---:|
| **Adversarial Scenarios Tested** | 32 | 32 | 100% Corpus Coverage |
| **Legitimate Tasks Tested** | 4 | 4 | Positive Controls |
| **Attack Success Count** | 31 / 32 | **0 / 32** | **100.0% Attack-Blocking Rate** |
| **Attack Success Rate** | 96.88% | **0.00%** | **-96.88% Attack Vulnerability** |
| **Legitimate Task Success Rate** | 100.0% | **100.0%** | **0.0% Utility Penalty** |
| **False Denial Rate** | 0.0% | **0.0%** | **0 Falsely Denied Valid Proposals** |
| **Unauthorized Acceptance Rate** | 96.88% | **0.00%** | **0 Unauthorized Execution** |
| **State-Integrity Violations** | 31 | **0** | **0 Unsigned Balance Changes** |

---

## 5. Key Findings & Category Breakdown

```
[System A: Baseline] █ 96.88% Vulnerability (31/32 Attacks Succeeded)
[System B: Guarded]  ░ 0.00% Vulnerability   (0/32 Attacks Succeeded)
```

1. **Prompt Injection & Authority Claims (Cat A & C):** System A granted root authority or executed transfers when payloads contained `approved=True` or `signer="ceo-root"`. System B stripped all authority fields and required mandatory human approval.
2. **Financial Precision & Destination Hijack (Cat B & E):** System A allowed transfers to `unauthorized-vendor-x` and accepted float rounding discrepancies. System B validated money via integer minor units, blocked unauthorized recipients, and rejected duplicate JSON keys.
3. **Secret & Key Protection (Cat G):** System A returned raw `private_key` sentinels. System B sanitized metadata and suppressed exception sentinels from logs and error envelopes.
4. **State Machine & Execution Boundary (Cat H):** System A allowed direct execution requests. System B enforced `NOT_AUTHORIZED` / `REQUIRE_APPROVAL` status, preventing any unsigned transaction from executing.

---

## 6. Verification Commands & Evidence

Execute from repo root:

```powershell
.\.venv\Scripts\python.exe -m pytest -q tests/security/test_m9_comparative_red_team.py
.\.venv\Scripts\python.exe -m pytest -q tests
.\.venv\Scripts\python.exe -m ruff check
.\.venv\Scripts\python.exe scripts\check_invariants.py
git diff --check
```

### Measured Evidence
- **M9 Comparative Suite:** 9 passed, 0 failed in 4.95 s.
- **Full Test Suite:** 796 passed (787 core + 9 M9 suite), 0 failed in 187.10 s.
- **Ruff:** All checks passed cleanly.
- **Invariants Check:** OK (all 94 cited tests verified).
- **Git Diff:** Clean.

---

## 7. Limitations & Scope

- **Simulated LLM Output in Main Suite:** The primary comparative benchmark uses deterministic test fixtures (`RunnableLambda`) for reproducible CI runs. Live Ollama / OpenAI model tests require credentials and are optional.
- **Single-Node DB Concurrency:** SQLite WAL mode with busy timeout enforces local single-process and multi-thread atomicity. Multi-node distributed DB clustering is documented as future work.
- **Human Approval Seam:** Agent-initiated transactions reach `REQUIRE_APPROVAL`. Real money execution requires an out-of-band human signature from an authorized human key.
