# FIN//GUARD Architecture and Threat Boundaries

## System Overview

```
 NL request / structured tx / MCP call            [UNTRUSTED]
        |
        v
 ai/ (analyzer, prompts, schemas, model)  -- extraction only, output validated, never authoritative
        |
        v
 core/ (Transaction, canonical, authority, enums, errors)  -- typed domain, canonical hash
        |
        v
 decision/engine.py  --> identity/registry  --> nonce claim (replay)  --> policy/ (parser, rules, engine)
        |                                                          \--> risk/ (destination, temporal, velocity, engine)
        v
 DecisionReceipt (stored)  -- REQUIRE_APPROVAL --> approvals/service.py (hash-bound, expiring, separate approver)
        |
        v
 signing/gate.py  -- re-validates EVERYTHING immediately before signing --> crypto/ (keystore, signing, hashing, encryption)
        |
        v
 simulator/service.py (synthetic execution)        audit/ledger.py (hash chain) + audit/nonce_store.py
```

## Trust Boundaries

- **B1 (Model/Caller -> Core Validation)**: Unauthenticated text/JSON from LLMs or CLI callers is strictly UNTRUSTED. Validation occurs at input schema deserialization.
- **B2 (Decision Engine -> Signing Gate)**: The `SigningGate` does NOT trust prior in-memory state or flags. It re-verifies stored `DecisionReceipt` / `Approval` records and recomputes `tx_hash` from source database state before creating signature.
- **B3 (Process -> Keystore)**: Key material is unlocked using Argon2id + AES-GCM and kept in memory only when signing.
- **B4 (Process -> Database)**: Database rows are assumed targetable by hostile edits. Hash-chain ledgers and canonical receipt hashes provide tamper-detection.
- **B5 (MCP Client -> MCP Server)**: MCP tools are untrusted clients. Actor identities are server-bound; signing/approval operations are strictly omitted from MCP tool definitions.

## State Transition Machine

Target transitions in domain model (`finguard/core/enums.py` & `finguard/decision/engine.py`):

| Current State | Target State | Trigger / Condition |
| :--- | :--- | :--- |
| `CREATED` | `PENDING_APPROVAL` | Decision Engine output `REQUIRE_APPROVAL` |
| `CREATED` | `BLOCKED` | Authority violation, policy deny, replay attempt, or invalid identity |
| `CREATED` | `APPROVED` | Decision Engine output `ALLOW` (automatic approval for low-risk) |
| `CREATED` | `FAILED` | Exception during evaluation or database error |
| `PENDING_APPROVAL` | `APPROVED` | `ApprovalService.approve_transaction()` by authorized approver |
| `PENDING_APPROVAL` | `BLOCKED` | `ApprovalService.deny_transaction()` or approval expiry |
| `PENDING_APPROVAL` | `FAILED` | System failure during approval processing |
| `APPROVED` | `SIGNED` | `SigningGate.sign_transaction()` succeeds |
| `APPROVED` | `FAILED` | Signing failure or key missing |
| `SIGNED` | `EXECUTED` | Simulator executes transaction |
| `SIGNED` | `FAILED` | Simulation/execution failure |
| `BLOCKED` | *(Terminal)* | - |
| `EXECUTED` | *(Terminal)* | - |
| `FAILED` | *(Terminal)* | - |

### Reconciliation with Section 11 & Day 1 Baseline Findings
- In the initial Day-1 code, `DecisionEngine.decide` transitions allowed transactions to `CREATED` in database records, whereas the state table specifies `CREATED -> APPROVED` or `CREATED -> PENDING_APPROVAL / BLOCKED`.
- Nonce claim and state persistence currently span multiple independent DB sessions in `DecisionEngine.decide()`, causing non-atomicity risks during crashes between steps (to be resolved in F3).
