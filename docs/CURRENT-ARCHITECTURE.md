# FIN//GUARD Current Architecture Map & State Audit

**Date**: 2026-10-08  
**Repository**: `hickytani/finCLI` (Package: `finguard`)  
**Branch**: `main` / `fg-401-llm-evaluation`  
**Thesis**: Autonomous financial agents must operate with the reasoning component (LLM) treated as an **UNTRUSTED principal**. The LLM may propose actions, but a deterministic, cryptographically enforced gateway decides, approves, signs, and executes.

---

## 1. Architectural Pipeline Flow

```text
 natural language request / tool call
                  │  [UNTRUSTED]
                  ▼
        ┌───────────────────┐
        │   LLM / Provider  │ (Extraction, non-authoritative JSON parsing)
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ ExtractionResult  │ (Pydantic validation, authority field stripping)
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │   MCP Boundary    │ (FastMCP / stdio, rate-limited, tool restrictions)
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ M4 Orchestrator   │ (Step/tool budget, deadline, budget tracking)
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ M3.1 Intent       │ (NFC canonicalization, alias resolution)
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │ M3.2 Guardrails   │ (Deny-by-default capability & limit checks)
        └─────────┬─────────┘
                  │
                  ▼
        ┌───────────────────┐
        │  DecisionEngine   │ (Policy evaluation, risk score, receipt generation)
        └─────────┬─────────┘
                  │
        ┌─────────┴─────────┐
        ▼                   ▼
 ┌──────────────┐    ┌──────────────┐
 │    BLOCK     │    │ REQUIRE_APPR │
 └──────────────┘    └──────┬───────┘
                            │ (Out-of-band human/policy authority)
                            ▼
                     ┌──────────────┐
                     │ ApprovalSvc  │ (Hash-bound, expiring, approver != maker)
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ SigningGate  │ (Ed25519 CAS state check, binds checked bytes)
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ SimulatorSvc │ (Integer minor-unit balances, CAS execution)
                     └──────┬───────┘
                            │
                            ▼
                     ┌──────────────┐
                     │ AuditLedger  │ (Sequenced hash-chain, signed checkpoints)
                     └──────────────┘
```

---

## 2. Comprehensive Component Matrix

| Component | Responsibility | Trust Level | Authority Level | Inputs | Outputs | Persistent State | Security Boundary | Failure Behavior | Implementation Status |
|---|---|---|---|---|---|---|---|---|---|
| **LLM / Provider** (`finguard.ai`) | Extract financial intent from natural language | UNTRUSTED | None (0) | NL prompt text | Raw JSON / text | None | B1 (Model boundary) | Fail-closed (`extraction_success=False`) | IMPLEMENTED (Ollama + Mock + Compromised) |
| **ExtractionResult** (`finguard.ai.provider`) | Structurally parse & strip authority fields | SEMI-TRUSTED | None (0) | Raw dictionary | `ExtractionResult` Pydantic model | None | B1.1 (Parser schema) | Strips authority fields & records in `authority_fields_detected` | IMPLEMENTED |
| **MCP Security Boundary** (`finguard.mcp`) | Rate-limit & route MCP requests | UNTRUSTED | None (0) | JSON-RPC tool calls | Propose / summary responses | In-memory session stats | B5 (MCP surface) | Rejects forbidden tools & authority inputs (`NOT_AUTHORIZED`) | IMPLEMENTED |
| **M4 Bounded Orchestrator** (`finguard.agent.orchestrator`) | Enforce step budget, tool limit, deadline | TRUSTED | Boundary Enforcer | `OrchestrationRun` config | Step execution status | None | B4 (Orchestration budget) | `OrchestrationBudgetExceeded` | IMPLEMENTED |
| **M3.1 Structured Intent** (`finguard.agent.intent`) | Canonicalize strings, resolve account aliases | TRUSTED | Input Validator | Raw intent proposal | Validated `StructuredIntent` | `AccountRegistry` DB | B3.1 (Intent validation) | `IntentValidationError` / `BLOCK` | IMPLEMENTED |
| **M3.2 Agent Guardrails** (`finguard.agent.guardrails`) | Check capability grants & financial limits | TRUSTED | Enforcer | `StructuredIntent` + Actor | `GuardrailDecision` | DB identity registry | B3.2 (Capability guardrail) | `GUARDRAIL_BLOCKED` | IMPLEMENTED |
| **DecisionEngine** (`finguard.decision`) | Authoritative risk scoring & policy decision | TRUSTED | Authoritative Gateway | Validated Transaction | `DecisionReceipt` | DB transactions & receipts | B2 (Core decision) | Fail-closed (`BLOCK`) | IMPLEMENTED |
| **ApprovalService** (`finguard.approvals`) | Hash-bound human maker-checker approval | HIGHLY TRUSTED | Authoritative | Receipt ID + Approver Key | `ApprovalRecord` | DB approval table | B6 (Approval boundary) | `ApprovalError` / `EXPIRED` | IMPLEMENTED |
| **SigningGate** (`finguard.signing`) | Re-verify stored facts & sign Ed25519 signature | HIGHLY TRUSTED | Authoritative Signer | Tx + Receipt + Approval | Ed25519 Signature | DB transaction state | B3 (Keystore process) | `SigningError` (CAS state rollback) | IMPLEMENTED |
| **FinancialSimulator** (`finguard.simulator`) | Execute transfer in integer minor units | HIGHLY TRUSTED | Execution Gateway | Signed Transaction | Balance updates | DB account balances | B6 (Execution boundary) | Rollback & `ExecutionError` | IMPLEMENTED |
| **AuditLedger** (`finguard.audit`) | Sequenced, hash-chained append log & checkpoints | CRITICAL | Audit Authority | Event / Receipt / Tx payload | `AuditEntryRecord` + Signed Checkpoint | DB SQLite triggers + checkpoint table | B4 (Database tampering) | Aborts on row edit/deletion | IMPLEMENTED |

---

## 3. Operational Analysis

### What Works Today
- **Exact Money & Canonical v2**: All money paths use integer minor units (`Money` class). Zero `float` in money paths (`test_no_float_money` AST test passes).
- **CAS Signing & Lifecycle Transitions**: SQLite `BEGIN IMMEDIATE` transactions, compare-and-swap state machine (`CREATED -> PENDING_APPROVAL / APPROVED -> SIGNED -> EXECUTED`).
- **Sequenced Audit Ledger & Checkpoints**: Monotonic `seq`, SQLite trigger defense against UPDATE/DELETE, Ed25519 signed checkpoints.
- **MCP Security Boundary (`finguard.mcp`)**: Structural exclusion of signing/approval/keystore tools; static `actor_id` binding.
- **FG-401 LLM Evaluation Harness (`finguard.evaluation`)**: 52-case adversarial catalog across 42 categories, exact Wilson 95% confidence interval scorecards.

### What is Deterministic vs. LLM-Dependent
- **Deterministic**: Account resolution, capability checking, authority policy rules, risk scoring, CAS state machine, Ed25519 signing, ledger hashing, simulation balance movement.
- **LLM-Dependent**: Extracting `amount`, `currency`, `recipient_alias`, and `reason` from raw natural language text. LLM output is strictly treated as non-authoritative candidate proposals.

### Current Workflow & Demonstrability Gaps
- **CLI Commands**: CLI subcommands exist for key management (`finguard key`), identity management (`finguard identity`), transaction proposals (`finguard tx`), approval (`finguard approval`), audit (`finguard audit`), and redteam attacks (`finguard attack`).
- **Agent Loop Gap**: Currently, running an agent request through natural language requires invoking `LLMPipeline.process_request(...)` via python scripts or evaluation runner. There is no top-level `finguard agent run --request "..."` CLI command exposing the composed agent reasoning/replanning loop to end-users.
- **Composed Agentic Attack Evaluation Gap**: FG-401 evaluated isolated prompt extractions against the pipeline. Multi-step composed attacks against the agent loop (e.g., replanning attacks, tool budget expansion attempts, observation tampering) require dedicated composed test coverage.

---

## 4. Architectural & Security Boundary Verification

1. **Model Output Cannot Grant Authority**: Authority fields (`approved`, `authorized`, `signer`, `signature`, `execute`, `grant_capability`, `private_key`, `secret`, `capabilities`, `max_steps`, `financial_limit`, etc.) are stripped by `ExtractionResult` and `MCPSecurityBoundary` before reaching downstream core modules.
2. **Import Isolation**: `finguard.ai` and `finguard.evaluation` have zero imports of `crypto.keystore`, `signing`, `approvals.service`, or `simulator.service` (enforced by AST tests).
3. **Out-of-Band Approval Boundary**: Autonomous agents can propose transactions up to their configured limit, but can NEVER approve or sign transactions. All high-risk proposals return `REQUIRE_APPROVAL` and stop.
