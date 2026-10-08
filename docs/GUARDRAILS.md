# FIN//GUARD 9-Layer Defense-in-Depth Architecture (M6)

## Overview: Prompt vs. Deterministic Security

A fundamental thesis of **FIN//GUARD** is that **prompt engineering and LLM classifiers do not constitute security**. Prompt guidance improves model compliance, but deterministic boundaries enforce authority.

```text
Layer 1 — Model Prompt Guidance        (Behavioral — NOT SECURITY)
Layer 2 — Structured Output Schema     (Parsing    — NOT AUTHORIZATION)
────────────────────── DETERMINISTIC SECURITY BOUNDARY ──────────────────────
Layer 3 — MCP Security Boundary        (Rate limits & Tool Access Control)
Layer 4 — M4 Bounded Orchestration     (Budget, Step & Timeout Enforcement)
Layer 5 — M3.1 Structured Intent       (Canonicalization & Alias Resolution)
Layer 6 — M3.2 Agent Guardrails        (Deny-by-Default Capability Checks)
Layer 7 — Authoritative DecisionEngine (Policy Rules & Risk Scoring)
Layer 8 — Approval, Signing & Exec    (Out-of-band Human/Policy Authority)
Layer 9 — Audit Ledger & Checkpoints   (Sequenced, Signed Audit Evidence)
```

---

## The 9 Layers Detailed

### Layer 1 — Model-Level Guidance
- **Purpose**: System prompt instructions and JSON mode constraints for Ollama / LLM providers.
- **Security Designation**: **NON-SECURITY (Behavioral Only)**.
- **Function**: Helps the LLM extract structured intent correctly from user prompts. If an attacker bypasses Layer 1 (e.g. prompt injection), downstream deterministic layers contain the attack.

### Layer 2 — Structured Output Schema (`ExtractionResult`)
- **Purpose**: Strongly typed Pydantic models (`finguard.ai.schemas`, `finguard.ai.provider`).
- **Security Designation**: **PARSING / SANITIZATION**.
- **Function**: Strips all 24 known authority-shaped fields (`approved`, `authorized`, `signer`, `signature`, `private_key`, `secret`, `grant_capability`, etc.) and non-standard extra keys before proposals reach core boundaries.

### Layer 3 — MCP Security Boundary (`finguard.mcp`)
- **Purpose**: Untrusted-caller rate limiting and tool access control.
- **Security Designation**: **DETERMINISTIC SECURITY BOUNDARY**.
- **Function**: Structurally excludes signing (`sign_transaction`), approval (`approve_transaction`), and key export (`get_private_key`). Binds `actor_id` to server session configuration. Always returns `authorization_status = "NOT_AUTHORIZED"`.

### Layer 4 — M4 Bounded Orchestration (`finguard.agent.orchestrator`)
- **Purpose**: Enforces hard execution budgets.
- **Security Designation**: **DETERMINISTIC SECURITY BOUNDARY**.
- **Function**: Tracks step count (`max_steps`), tool call ceiling (`max_tool_calls`), and execution deadline. Neither LLM output nor replanning can reset or expand orchestration bounds.

### Layer 5 — M3.1 Structured Intent Boundary (`finguard.agent.intent`)
- **Purpose**: Canonicalizes strings and resolves account aliases.
- **Security Designation**: **DETERMINISTIC SECURITY BOUNDARY**.
- **Function**: Applies Unicode NFC normalization and resolves aliases against the database `AccountRegistry`. Prevents homoglyph, zero-width, and script-mixing recipient spoofing.

### Layer 6 — M3.2 Agent Guardrails (`finguard.agent.guardrails`)
- **Purpose**: Enforces explicit agent capabilities and single-transaction ceilings.
- **Security Designation**: **DETERMINISTIC SECURITY BOUNDARY**.
- **Function**: Checks deny-by-default capabilities (`transaction.propose`, `recipient.resolve`). Rejects any transaction exceeding the agent's pre-configured limit (`max_single_tx_limit_minor`).

### Layer 7 — Authoritative DecisionEngine (`finguard.decision`)
- **Purpose**: Evaluates system policy rules and risk scores.
- **Security Designation**: **AUTHORITATIVE SECURITY GATEWAY**.
- **Function**: Compares transaction details against `PolicyEngine` rules. Generates signed `DecisionReceipt` with verdict (`ALLOW`, `BLOCK`, or `REQUIRE_APPROVAL`).

### Layer 8 — Approval, Signing & Execution (`finguard.approvals`, `finguard.signing`, `finguard.simulator`)
- **Purpose**: Out-of-band authority operations.
- **Security Designation**: **HIGHLY TRUSTED AUTHORITATIVE CORE**.
- **Function**: Autonomous agents can NEVER enter this layer directly. High-risk transactions require hash-bound, expiring human approvals (`ApprovalService`). Ed25519 signing (`SigningGate`) re-validates stored facts and executes via Compare-and-Swap state transitions.

### Layer 9 — Audit Ledger & Signed Checkpoints (`finguard.audit`)
- **Purpose**: Tamper-evident record of all events, decisions, and checks.
- **Security Designation**: **AUDIT AUTHORITY**.
- **Function**: Append-only SQLite triggers abort any attempt to edit or delete historical audit entries. Ed25519-signed checkpoints cover monotonic sequence prefixes.
