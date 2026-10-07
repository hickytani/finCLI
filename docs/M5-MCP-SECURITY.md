# M5 — Secure MCP Boundary

**Status:** Implemented (branch `m5-mcp-security`)
**Date:** 2026-10-07
**Milestone:** M5

---

## 1. Threat Model

An MCP client (including an LLM acting as MCP agent) is **fully untrusted**:

| Threat | Mitigation |
|--------|-----------|
| MCP input carries authority-shaped fields (`approved`, `signer`, `execute`) | Rejected at first validation gate before any core call |
| MCP caller tries to escalate capabilities | Capabilities come from signed IdentityRegistry only |
| MCP caller tries to set orchestration bounds (`max_steps`, `deadline`) | Bounds set by server config; extra fields rejected by Pydantic `extra="forbid"` |
| MCP caller supplies float amount | Rejected before Money parsing |
| Prompt injection in `reason` text | Reason is plain string data; deterministic guardrails ignore text content |
| MCP tool output contains `{approved: true, authorized: true}` | Tool output stored as data in orchestrator observations; never changes security state |
| MCP caller tries to sign/approve/execute | Methods do not exist on `MCPSecurityBoundary` |
| Error messages leak secrets/keys/paths | All error messages are safe; keystore never imported |

---

## 2. MCP Trust Boundary

```text
┌─────────────────────┐
│   LLM / AI Agent   │  ← UNTRUSTED
└──────────┬──────────┘
           │ MCP tool call
           ▼
┌─────────────────────┐
│  MCPSecurityBoundary│  ← M5 BOUNDARY (this package)
│  finguard/mcp/      │    - authority-field rejection
│  boundary.py        │    - input validation
│                     │    - rate limiting
│                     │    - actor identity from server config
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│  BoundedOrchestrator│  ← M4 (max_steps/deadline immutable)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ StructuredIntent    │  ← M3.1 (canonical intent binding)
│ Boundary            │
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ AgentGuardrails     │  ← M3.2 (deterministic preflight)
└──────────┬──────────┘
           │
           ▼
┌─────────────────────┐
│ DecisionEngine      │  ← AUTHORITATIVE
└──────────┬──────────┘
           │ approval / signing
           ▼
┌─────────────────────┐
│ Financial Execution │  ← unreachable from MCP
└─────────────────────┘
```

**No alternate path exists:**
- `LLM → MCP → DB` ✗
- `LLM → MCP → approval` ✗  
- `LLM → MCP → signing` ✗
- `LLM → MCP → execution` ✗
- `MCP → policy mutation` ✗
- `MCP → capability grant` ✗

---

## 3. Allowed MCP Tools

| Tool | Type | Flows through |
|------|------|--------------|
| `propose_transaction` | Proposal only | M4 → M3.1 → M3.2 → DecisionEngine |
| `get_decision` | Read-only | DB query (receipt only) |
| `list_transactions` | Read-only | DB query (actor-scoped) |
| `get_audit_proof` | Read-only | Audit ledger query |

---

## 4. Prohibited Tools (structurally absent)

The following operations have **no method** on `MCPSecurityBoundary` and are absent from `finguard/mcp/`:

```
approve_transaction    sign_transaction    execute_transaction
grant_capability       set_policy          set_signer
modify_authorization   create_key          delete_key
export_key             get_private_key
```

Enforced by: method absence + import-boundary test + attack tests.

---

## 5. Request Validation

Every MCP request passes through two gates before touching any core code:

**Gate 1 — Authority-field rejection** (`_reject_authority_shaped_input`):
Rejects any input containing: `approved`, `authorized`, `signer`, `signature`, `execute`, `execution_state`, `policy_override`, `grant_capability`, `admin`, `root`, `signing_key`, `approve`, `sign`, `private_key`, `secret`, `credential`

**Gate 2 — Pydantic model validation** (`ProposeTransactionRequest` etc.):
- `extra="forbid"` — unknown fields rejected
- `frozen=True` — immutable after construction
- Float amounts rejected (`amount` must be `str | int`)
- Size limits on all string fields (reason ≤ 1024 bytes, identifiers ≤ 128 bytes)
- Currency normalised to uppercase and validated alphabetic

---

## 6. Output Trust Model

MCP tool responses are **data**, not authority:

- `ProposeTransactionResponse.authorization_status` is always `"NOT_AUTHORIZED"`
- Responses carry `decision` (allow/block/require_approval) — this is information, not permission
- Response models never contain: private keys, signing keys, passwords, credentials, raw DB metadata
- `AuditProofResponse` exposes only: seq, hashes, action, actor_id, result

---

## 7. M4 Integration

`MCPSecurityBoundary` creates a `BoundedOrchestrator` from **server configuration only**:

```python
self._orchestrator = BoundedOrchestrator(
    max_steps=int(cfg.get("max_steps", 5)),
    max_tool_calls=int(cfg.get("max_tool_calls", 3)),
    deadline_seconds=int(cfg.get("deadline_seconds", 300)),
    allowed_capabilities=cfg.get("allowed_capabilities", ("transaction.propose",)),
    ...
)
```

The MCP caller cannot supply `max_steps`, `deadline`, `capabilities`, or `financial_limit` — these are rejected as unknown fields by Pydantic.

---

## 8. M3.1 Integration

Proposals are submitted through `StructuredIntentBoundary`:

```python
boundary = StructuredIntentBoundary(
    actor_id=self._actor_id,   # server-configured, never from MCP input
    session_id=self._session.session_id,
)
decision_result = boundary.submit(intent_dict)
```

The actor identity is bound by the `MCPSecurityBoundary` constructor — the MCP caller cannot change it.

---

## 9. M3.2 Integration

`StructuredIntentBoundary.submit()` calls `AgentGuardrails.evaluate()` internally. The guardrails check:
- Capability is granted by the signed registry
- Action is not privileged (approve/sign/execute blocked)
- Amount is within the signed authority limit
- Source and destination are explicitly granted (no wildcards for agents)
- Currency matches the signed registry

This path is **mandatory** — there is no MCP bypass.

---

## 10. Approval Boundary

When `DecisionEngine` returns `REQUIRE_APPROVAL`:
- `propose_transaction` returns `approval_required=True, authorization_status="NOT_AUTHORIZED"`
- The orchestration run transitions to `APPROVAL_REQUIRED` state — not `COMPLETED`
- **MCP does not auto-approve, auto-sign, or auto-execute**
- There is no `approve_transaction` MCP tool

---

## 11. Replay / Correlation

- Each `propose_transaction` call generates a fresh `correlation_id` (UUID) in the boundary
- The `request_id` from the MCP caller is echoed for tracing — it is not used for authorization
- Idempotency is handled by the existing M2/M3 nonce + idempotency_key mechanism in `StructuredIntentBoundary`
- No second ledger is created; the existing `AuditLedger` is reused

---

## 12. Audit Behaviour

MCP events are appended to the **existing** `AuditLedger` as supplemental entries.

Actions recorded:
- `MCP_PROPOSE_RECEIVED` — before any validation
- `MCP_PROPOSE_REJECTED` — after intent validation failure
- `MCP_PROPOSE_SECURITY_ERROR` — after a SecurityError
- `MCP_PROPOSE_DECIDED` — after a core decision

**Atomicity note:** MCP supplemental audit entries are NOT atomic with the core financial transaction. Atomicity is guaranteed only by the existing `DecisionEngine` path. This is documented honestly and matches M2/M3 behaviour for intent-boundary supplemental events.

If an audit append fails, it is logged at `ERROR` level and does NOT block the MCP response (mirrors the FG-805 pattern from `incidents/service.py`).

---

## 13. Error Handling

All errors are returned as structured `MCPBoundaryError` instances:

```json
{"error": {"code": "MCP_INPUT_INVALID", "message": "...", "retryable": false, "correlation_id": "..."}}
```

Error messages NEVER contain:
- Private keys or key material
- Filesystem paths containing `.finguard`
- Database credentials
- Stack traces or internal module names

---

## 14. Secret Boundary

`finguard/mcp/boundary.py` does NOT import:
- `finguard.crypto.keystore` — private key access
- `finguard.signing` / `finguard.signing.gate` — signing primitives
- `finguard.approvals.service` — approval service
- `finguard.simulator.service` — financial execution

Enforced by: import-boundary test (`test_mcp_boundary_does_not_import_forbidden_module`) and source-scan test (`test_mcp_boundary_source_does_not_reference_forbidden_import`).

---

## 15. Attack Suite

**File:** `tests/security/test_mcp_attacks.py`

20 attack categories, all green:
1. Malformed MCP requests
2. Unknown / extra fields
3. Oversized input
4. Authority-shaped fields (17 variants)
5. Unsupported capability
6. Capability escalation
7. Amount-limit bypass
8. Approval bypass
9. Signing bypass
10. Execution bypass
11. Policy override
12. Hostile tool output
13. Prompt injection text (8 injection variants)
14. Replay
15. Correlation mismatch
16. Secret leakage through errors
17. Forbidden privileged imports (source-level check)
18. MCP bypass of M3.2
19. MCP bypass of M4 bounds
20. Read-only tool mutation attempt

---

## 16. Future LLM Integration

When `FG-401` (LLM provider layer) is implemented, the LLM plugs in **above** the MCP boundary:

```text
LLMProvider.extract(request) → ExtractionResult
    ↓ (amount STRING, account ALIAS — never authority fields)
MCPSecurityBoundary.propose_transaction(...)
    ↓ (all existing M5 gates apply)
M4 → M3.1 → M3.2 → DecisionEngine
```

The LLM:
- **Cannot** set `actor_id`, `session_id`, `capabilities`, `max_steps`, `deadline`
- **Cannot** produce `approved`, `signer`, `signature`, `execute` as authority
- **Cannot** bypass guardrails by injecting authority text
- **Can** produce a `ProposeTransactionRequest`-compatible dict with amount (string) and recipient (alias)

The evaluation harness (`FG-401`) will measure: valid-JSON rate, extraction accuracy, injection resistance, authority-escalation attempts — all against this boundary.

---

## 17. Known Limitations

- MCP server transport is implemented via `FastMCP` (optional dep `mcp>=1.0.0`). The server factory is in `finguard/mcp/server.py`. No live MCP Inspector walkthrough yet — that is part of FG-501 delivery.
- Supplemental audit entries are not atomic with core decisions (documented above).
- Per-session rate-limiting is in-memory only; it does not persist across process restarts.
- The `get_decision` and `get_audit_proof` tools query the local SQLite database; in a multi-process deployment, the database must be shared or these tools must route to a read replica.
- MCP Streamable HTTP transport is not yet configured (stdio default only).
- No live demo against a real MCP client yet (planned for FG-501 full delivery).
