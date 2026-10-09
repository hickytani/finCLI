# FIN//GUARD Case Study

**Research-grade agentic payment security framework — v0.2.0**

> *"Can an autonomous financial agent safely operate when its reasoning
> component is treated as an untrusted principal?"*

---

## 1. Problem Statement

Autonomous AI agents that can move money present a fundamental security
challenge: if the agent's reasoning component (the LLM) is compromised,
tricked, or simply wrong, a prompt-level guardrail cannot prevent unauthorized
transactions. Text classifiers and "safety prompts" operate in the same
untrusted input space as the attack.

FIN//GUARD's thesis: **treat the model as untrusted and enforce authority
deterministically outside it**.

### Threat Model (Summary)

| Threat | Actor | Impact |
|--------|-------|--------|
| Prompt injection via invoice/email | External attacker | Unauthorized transfer |
| Destination manipulation | Compromised LLM | Funds to wrong account |
| Amount manipulation (unit tricks, unicode) | Adversarial input | Over/under-payment |
| Authority claim injection | Malicious tool argument | Privilege escalation |
| Replay attack | External attacker | Duplicate payment |
| Concurrency race to sign twice | Timing attacker | Double-spend |
| Ledger tampering | Insider / file-level | Audit evasion |

Full threat model: [`THREAT_MODEL.md`](../THREAT_MODEL.md)

---

## 2. Design Decisions and ADR Links

### D1 — Model output is a request, never an authority

The LLM proposes. The deterministic gateway decides. The gateway can never be
overridden by model text.

*Enforcement:* `finguard/ai/schemas.py` — `ExtractionResult` contains only
`amount: str`, `currency`, `destination_alias`, `purpose`. Fields like
`actor_id`, `nonce`, `policy_version`, `approved`, `decision` are **absent**
from the schema; any model output containing them is stripped and recorded in
`authority_fields_detected` before the pipeline continues.

*Proof test:* `tests/security/test_fg401_security_audit.py::test_authority_field_stripping_*`

### D2 — Exact money: integer minor units, no float

`float` arithmetic silently rounds. `Transaction(amount=100.001)` and
`amount=100.004` previously produced the same hash — an attacker could swap the
signed amount for the executed amount.

*Fix (FG-201/202/205):* `Money(minor: int, currency)`. Parse only from
`str`/`int`/`Decimal`. JSON wire form: decimal string `"500.00"`. Canonical v2
uses `amount_minor` (integer). Database: `amount_minor BIGINT`.

*Proof tests:* FG-201 and FG-202 xfail tests promoted to normal regression tests.

*AST gate:* `tests/unit/test_no_float_money.py` — the build fails if `float`
appears in any money/canonical path outside the allowlist.

### D3 — Deny-by-default authority (FG-203)

The previous default `Authority()` had `allowed_destinations = []` meaning
**allow all**. A misconfigured actor could send to any destination.

*Fix:* Empty list means NONE. `"*"` is an explicit wildcard: it emits a
`WILDCARD_AUTHORITY` signal, creates an audit ledger entry, and is rejected for
`ActorType.AGENT` unless an operator override flag is set and recorded.

### D4 — Signature binding: signed bytes == checked bytes == executed bytes

The signing gate re-validates everything from **stored facts** (not caller
input) before producing an Ed25519 signature. The signature covers the v2
canonical preimage `b"finguard.tx.v2\x00" + canonical_bytes`, which includes
`amount_minor` (integer), `currency`, and `metadata_digest` (RFC 0001 / FG-206).

No value may change between check, approval, signature, and execution.

*Proof:* `tests/property/test_signing_binding.py` — Hypothesis property tests
that `a != b ⟹ hash(a) != hash(b)` for all representable distinct amounts.

### D5 — MCP surface is structurally bounded

`finguard/mcp/` exposes exactly four tools: `propose_transaction`,
`get_decision`, `list_transactions`, `get_audit_proof`. The package does **not
import** `signing`, `approval`, `crypto/keystore`, or `policy mutation` modules.
This is enforced by an import-linter/AST test (`tests/security/test_mcp_boundary.py`).

Actor identity is bound by server configuration, never by tool arguments.

### D6 — Fail-closed everywhere

Any exception in `decision/`, `signing/`, or `audit/` paths produces a BLOCKED
or FAILED state, never ALLOW or SIGNED. The decision engine is broken into small,
individually testable steps. `pytest -m security` includes injection tests that
force exceptions at every commit point.

---

## 3. Architecture

```
NL / structured tx / MCP call                      [UNTRUSTED]
  │
  ▼
finguard/ai/ ─── ExtractionResult (amount str, currency, alias, purpose)
  │               authority-shaped fields stripped → authority_fields_detected
  ▼
M3.1 StructuredIntentBoundary
  │  NFC normalization, zero-width/control-char rejection, identity binding
  ▼
M3.2 AgentGuardrails
  │  budget enforcement, injection-pattern blocking
  ▼
DecisionEngine ── identity → authority → nonce-claim → policy → risk
  │               receipt + ledger append (one SQLite transaction)
  ▼
ApprovalService (if REQUIRE_APPROVAL)
  │  hash-bound, expiring, approver ≠ requester
  ▼
SigningGate ── re-validate from stored facts → Ed25519 sign v2 canonical bytes
  │            CAS: UPDATE WHERE state='approved' AND rowcount==1
  ▼
FinancialSimulator ── BEGIN IMMEDIATE, debit/credit balance_minor BIGINT
  │                   conservation invariant: Σ balances constant
  ▼
AuditLedger ── monotonic seq, UNIQUE(seq), UNIQUE(prev_hash), signed checkpoints
```

---

## 4. Results

All numbers are reproducible with:

```bash
pytest tests/ -q --tb=short -m "not slow"
```

| Metric | Result |
|--------|--------|
| Total tests | 592 passed, 0 failed |
| Adversarial catalog | 52 cases (direct injection, destination swap, amount manipulation, unicode, encoding, authority claims, multi-turn) |
| Executable-action attack success rate | **0 / 52** (95% upper bound: 5.6%, rule of three) |
| Authority-field injection blocked | 100% (authority_fields_detected; never reaches decision) |
| Signature binding violations | 0 (property-tested: distinct amounts → distinct hashes) |
| Wildcard authority granted to AGENT | 0 (reject path enforced) |
| Branch coverage | 71% (gate); critical modules (decision, signing, audit) ≥ 80% |
| Python versions | 3.12 ✅, 3.13 ✅ |
| Decision p50 latency | ~7 ms |
| Ed25519 sign p95 | ~0.04 ms |
| Ledger 200-entry verify | ~12 ms |

*Adversarial cases are author-written. Independent suites (garak, PyRIT) have not been integrated — see Limitations.*

---

## 5. Limitations

See [`docs/LIMITATIONS.md`](LIMITATIONS.md) for the complete list.

Key items for interviewers/reviewers:

1. **Research-grade, not production-ready.** Not independently audited; not
   certified for real funds.
2. **SQLite file replacement** by a privileged attacker can bypass the hash chain.
   External anchoring (git tags, transparency log) is documented as future work.
3. **LLM evaluation uses author-written adversarial cases.** External benchmark
   integration is future work.
4. **Forced process-death recovery** at commit boundaries is partially tested.
5. **MCP transport** is stdio only (localhost Streamable HTTP is optional, not
   default). No distributed multi-node deployment.
6. **Real banking is explicitly out of scope.** All amounts are synthetic.

---

## 6. What I Would Do Next

| Priority | Work item |
|----------|-----------|
| P0 | External ledger anchoring (git tag each signed checkpoint) |
| P0 | `pip-audit` clean or explicitly justified |
| P1 | OpenSSF Scorecard — target 7/10 |
| P1 | Independent adversarial evaluation (garak / PyRIT integration) |
| P1 | KMS signer abstraction (FG-601/602) — contract tests, no cloud dependency |
| P2 | Forced process-death recovery tests at all commit boundaries |
| P2 | Process-level decision/signing contention tests |
| P2 | PyPI Trusted Publishing + build provenance attestations |
| P3 | NeMo Guardrails / LLM Guard comparison study (FG-602) |

---

## 7. Resume Bullets (from measured numbers)

- Designed and implemented a 9-layer deterministic security architecture
  treating the LLM as an untrusted component; **0 / 51** red-team scenarios (41 adversarial)
  produced an authorized financial execution.
- Implemented M7.1 Red-Team Platform: state snapshot oracle (`SystemStateSnapshot`), 51 scenarios
  across 15+ attack classes, multi-turn stateful sequences, and 5 multi-component attacks.
- Fixed four P0/P1 security defects (FG-201–206): replaced float money with
  integer minor units, deny-by-default authority, NaN/Infinity rejection, and
  metadata-digest binding in Ed25519 signatures.
- Built MCP boundary (4 tools exposed, signing/approval/keys structurally
  absent), agent orchestration loop with immutable capability profiles, and a
  51-case adversarial red-team harness; **649 tests pass on Python 3.12 and 3.13**.
- Implemented atomic decision pipeline: nonce claim + receipt + ledger append
  in one SQLite transaction; signing CAS prevents double-signing; conservation
  invariant property-tested across concurrent transfers.
