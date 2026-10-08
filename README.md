# FIN//GUARD — Security Architecture for Agentic Financial Systems

[![Python 3.12+](https://img.shields.io/badge/python-3.12%20%7C%203.13-blue.svg)](https://www.python.org/)
[![Build Status](https://img.shields.io/badge/tests-577%20passed-brightgreen.svg)]()
[![Security Audit](https://img.shields.io/badge/authority--violations-0-success.svg)]()
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

> **Core Research Thesis**: Can an autonomous financial agent safely operate when its reasoning component is treated as an **UNTRUSTED principal**?
>
> **Architectural Rule**: The AI can become more capable, but it must **NEVER become more authoritative**.

---

## 1. What is FIN//GUARD?

**FIN//GUARD** (`finguard`) is an open-source security architecture for financial agents. It treats Large Language Models (LLMs) as unprivileged, untrusted intent parsers.

AI agents moving money cannot be secured by prompting them to behave. In FIN//GUARD:
1. Model output is a **candidate proposal**, never an authority.
2. Enforcement lives **outside the model**: identity, authority, policy, risk, approval, signing, and execution.
3. A signature binds the **exact bytes** checked and executed.
4. Every decision generates a tamper-evident entry in a **sequenced, checkpoint-signed ledger**.
5. Any error, ambiguity, or missing evidence results in denial (**fail-closed**).

---

## 2. What the AI CANNOT Do

The autonomous agent is strictly isolated from core financial authority. **The agent CANNOT**:

| Prohibited Action | Security Mechanism |
|---|---|
| ❌ **Approve transactions** | Requires out-of-band human maker-checker approval (`ApprovalService`). |
| ❌ **Sign transactions** | Ed25519 keys live in an isolated process (`SigningGate`); LLM paths cannot import signing. |
| ❌ **Execute transfers** | `FinancialSimulator` requires a valid, signed decision receipt; agent cannot invoke execution. |
| ❌ **Grant itself capabilities** | Capability profiles are server-configured, deny-by-default, and immutable during a run. |
| ❌ **Modify security policy** | `PolicyEngine` rules are loaded strictly from verified configuration files. |
| ❌ **Modify financial limits** | Single-transaction ceilings and daily budgets are server-enforced (`M3.2` / `M4`). |
| ❌ **Impersonate signers** | Caller identity is bound to session configuration, not model output (`actor_id`). |
| ❌ **Access private keys** | Keystore modules are isolated from AI/MCP boundaries (`I11` leak-prevention). |
| ❌ **Extend execution budgets** | Step limits (`max_steps`) and deadlines are enforced deterministically by `M4 BoundedOrchestrator`. |

---

## 3. Architecture & Trust Boundaries

```text
 NL / Agent Request                                [UNTRUSTED INPUT]
       │
       ▼
 ┌───────────────┐
 │ LLM Provider  │ (Extraction only; output sanitized; non-authoritative)
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ ExtractionRes │ (Strips all 24 authority/key fields; records detection)
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ MCP Boundary  │ (FastMCP / stdio, rate-limited, tool restrictions)
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ M4 Bounded    │ (Enforces max_steps, tool call ceilings, deadlines)
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ M3.1 Intent   │ (NFC canonicalization, alias resolution)
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ M3.2 Guard    │ (Deny-by-default capability & financial limit checks)
 └───────┬───────┘
         │
         ▼
 ┌───────────────┐
 │ DecisionEngine│ (Evaluates policy rules, risk scores, generates receipts)
 └───────┬───────┘
         │
  ┌──────┴──────┐
  ▼             ▼
┌───┐     ┌───────────┐
│BLK│     │REQUIRE_APP│
└───┘     └─────┬─────┘
                │ (Out-of-band human approval)
                ▼
          ┌───────────┐
          │ApprovalSvc│ (Hash-bound, expiring, approver != maker)
          └─────┬─────┘
                │
                ▼
          ┌───────────┐
          │SigningGate│ (Ed25519 CAS state check, binds checked bytes)
          └─────┬─────┘
                │
                ▼
          ┌───────────┐
          │Simulator  │ (Integer minor units, CAS execution)
          └─────┬─────┘
                │
                ▼
          ┌───────────┐
          │AuditLedger│ (Sequenced hash-chain, signed checkpoints)
          └───────────┘
```

---

## 4. Quickstart & Agent Workflow Demo

### Installation
```bash
# Clone the repository
git clone https://github.com/hickytani/finCLI.git
cd finCLI

# Run full test suite (577 tests)
py -m pytest
```

### Demonstrating the Agent MVP Workflow
Run a natural language request through the deterministic FIN//GUARD security loop:

```bash
py -m finguard.cli.main agent run --request "Pay Alice INR 500 for design work"
```

#### Output Trace
```text
┌────────────────────────────────── REQUEST ──────────────────────────────────┐
│ Pay Alice INR 500 for design work                                           │
└─────────────────────────────────────────────────────────────────────────────┘
                             AGENT EXECUTION TRACE
┌────────┬────────────────────────────┬───────────────────────────────────────┐
│ Step   │ Type                       │ Description                           │
├────────┼────────────────────────────┼───────────────────────────────────────┤
│ 1      │ AGENT_RUN_STARTED          │ Orchestration run started for request │
│ 2      │ LLM_EXTRACTION             │ Extracted intent parameters from NL   │
│ 3      │ GUARDRAIL_CHECK            │ Evaluated against M4/M3.2/Decision    │
│ 4      │ REQUIRE_APPROVAL           │ Transaction requires human approval   │
└────────┴────────────────────────────┴───────────────────────────────────────┘
┌───────────────────────── SECURITY BOUNDARY RESULT ──────────────────────────┐
│ Final State: APPROVAL_REQUIRED                                              │
│ Decision: REQUIRE_APPROVAL                                                  │
│ Receipt ID: rcpt_89a7f102                                                   │
│                                                                             │
│ SECURITY BOUNDARY ENFORCEMENT:                                              │
│ • Autonomous agent CANNOT approve transactions.                             │
│ • Autonomous agent CANNOT sign transactions.                                │
│ • Autonomous agent CANNOT execute transactions.                             │
│ • Autonomous agent CANNOT grant capabilities or modify policy.              │
└─────────────────────────────────────────────────────────────────────────────┘
```

---

## 5. Security Scorecard & Benchmark Results

FIN//GUARD is evaluated against a 52-case adversarial attack dataset across 42 categories and 15 multi-step composed agent attack scenarios:

| Metric | Measured Value | 95% Wilson Confidence Interval |
|---|---|---|
| **Total Test Suite** | **577 passed, 0 failed** | **[99.36%, 100.0%]** |
| **Adversarial Evaluation Cases** | 52 cases (42 categories) | - |
| **Composed Agentic Attack Scenarios** | 15 scenarios | - |
| **Authority Violations Observed** | **0** | **[0.0%, 6.88%]** |
| **Financial Bypasses Observed** | **0** | **[0.0%, 6.88%]** |
| **Secret / Key Leaks** | **0** | **[0.0%, 6.88%]** |
| **Capability Escalations** | **0** | **[0.0%, 6.88%]** |
| **Budget / Bound Escapes** | **0** | **[0.0%, 6.88%]** |
| **Provider Failure Behavior** | Fail-Closed (100%) | [67.56%, 100.0%] |

---

## 6. Project Documentation
- [Architecture & State Map](docs/CURRENT-ARCHITECTURE.md)
- [9-Layer Guardrails Architecture](docs/GUARDRAILS.md)
- [Security Invariants Specification (I1 - I60)](docs/INVARIANTS.md)
- [FG-401 Evaluation & Results](docs/FG-401-LLM-EVALUATION.md)
- [MVP Limitations & Scope](docs/LIMITATIONS.md)

---

## 7. License
This project is licensed under the [MIT License](LICENSE).
