# FinGuard Phase 2 implementation report

> **Current consolidated status (latest verification):** This report now
> includes the product-first completion. FinGuard is a local-first security
> gateway between an AI agent and financial actions. The complete path is
> natural language -> real local Ollama/Qwen extraction -> validated request ->
> request-only SDK -> DecisionEngine -> human approval -> SigningGate -> local
> virtual simulator -> audit evidence. The current suite is **43 tests passed**.

## Current product implementation

The local model is `qwen3:0.6b` through Ollama. It extracts amount, currency,
destination, purpose, and advisory risk context. Pydantic validation rejects
malformed, ambiguous, overlong, or unsupported output. The model is untrusted:
its output is evidence only and cannot authorize execution.

`TreasuryAgent` has access only to request/inspection operations through
`FinGuardAgentClient`. It has no signing, key access, approval, self-approval,
policy mutation, identity mutation, authority grant, block override, or direct
simulator execution capability.

`DecisionEngine` independently validates signed identity, actor type, authority
limits, destinations, policy, deterministic risk, and nonce uniqueness. It
creates receipts and approval requests and fails closed on uncertainty.

`SigningGate` is the only application signing route. It rechecks the canonical
transaction hash, receipt, identity, current policy hash/version, risk/policy
decision, approvals, expiry, and nonce immediately before Ed25519 signing.

`FinancialSimulator` contains only virtual INR balances. It independently
verifies the stored transaction hash and Ed25519 signature, requires the
transaction to be signed, atomically moves virtual funds once, changes the
state to `executed`, and writes audit evidence. It is not exposed to the AI.

## Verified end-to-end demonstrations

The real Ollama model processed `Pay vendor-a INR 5000 for invoice 4471` and
created `TX-F8A005A5BAE1` with `require_approval`. After `approver-1` approved
the exact transaction, SigningGate signed it and the simulator moved INR 5,000
from `treasury` to `vendor-a`. Audit verification passed with all 67 entries
valid at that time.

A manipulated agent emitting an INR 1,000,000 request was blocked by the signed
identity limit and agent policy limit of INR 10,000. It could not reach approval,
signing, or execution. Direct simulator execution without an authorized signed
transaction was also blocked.

The default agent limit and mandatory human approval were intentionally
preserved. The earlier INR 50,000 example would conflict with those controls;
the implementation does not weaken security merely to make that example pass.

## Latest verification

```text
43 passed
```

The suite covers existing security controls plus local-AI validation,
full LLM-to-execution flow, simulator replay/signature checks, prompt
injection, direct bypass, and approval mutation defenses.

## Scope of this change

This revision extended the existing CLI-first FinGuard prototype; it did not
replace its cryptographic or policy foundations. The focus was establishing a
single fail-closed transaction-decision boundary and ensuring that an agent can
request, but cannot authorize, sign, or approve payments.

## Capabilities that already existed

| Area | Existing implementation retained |
|---|---|
| Identity | Signed YAML identity registry, rooted in an Ed25519 root signature |
| Cryptography | Ed25519 signatures; AES-256-GCM keystore; Argon2id password derivation |
| Integrity | Canonical transaction serialization and SHA-256 transaction hashes |
| Policy and authority | YAML policy engine, authority limits, destination allowlists, agent approval floor |
| Risk | Deterministic destination, velocity, temporal, amount, and authority signals |
| Approvals | Maker-checker approval records cryptographically bound to transaction hashes |
| Replay | SQLite-backed nonce tracking with a unique database constraint |
| Evidence | Hash-chained audit ledger, incidents, decision-receipt database model, and signed attestations |
| Interface/testing | CLI commands, attack scenario assets, and unit tests |

## What was added or changed

| Improvement | Exact implementation |
|---|---|
| Central authorization boundary | Added `finguard/decision/DecisionEngine`. It evaluates a request through signed identity, authority, policy, deterministic risk, approval requirement, decision receipt, and audit. |
| Fail-closed behavior | Unknown identities, actor-type claim mismatches, nonce/persistence conflicts, and evaluation exceptions return `BLOCK`; no exception is converted to `ALLOW`. |
| Decision evidence | Added canonical `DecisionReceipt` objects with transaction/actor identity, authority result, policy hash/version, deterministic risk, AI placeholder, approval state, final decision, reasons, timestamp, and receipt hash. Persisted receipts are linked to the existing receipt table. |
| CLI integration | `tx create` and `agent-request tx-create` now route through `DecisionEngine` instead of duplicating policy/risk/replay logic. Added `finguard decision inspect <tx-id>`. |
| Safe SDK | Added `FinGuardAgentClient` with transaction creation, inspection/status, analysis, and approval-status request. It deliberately does not provide signing, key export, self-approval, identity/policy changes, audit mutation, or decision override methods. |
| Treasury agent boundary | Added `TreasuryAgent`, which accepts only a constrained payment form and submits through the SDK. It audits accepted/denied tool actions. |
| Local model | Ollama `qwen3:0.6b` performs structured extraction; output remains advisory and is strictly validated. |
| Red-team harness | Added `RedTeamRunner`, which uses the real SDK for authority-escalation attempts and records forbidden-tool attempts. It does not claim adaptive LLM attacks. |
| Replay hardening | Updated `NonceStore.record` to attempt an atomic database insert and return `False` when a duplicate nonce wins the race. |
| Tests | Added three Phase 2 tests for authority hard-blocking, unknown-identity fail-closed behavior, and absence of SDK signing/self-approval methods. |
| Documentation | Added README and architecture, security, threat, model, dataset, reality-matrix, red-team, repository-audit, and this implementation-report documents. |

## Verification performed

`python -m pytest -q -p no:cacheprovider --basetemp .\\test-tmp4`

Result at that earlier Phase 2 checkpoint: **26 passed**. The test command used a workspace-local temporary
directory because the environment denied access to the existing Windows pytest
temporary/cache directory. Temporary verification directories were removed.

## Current limitations / not completed

The following are not implemented or measured, and are not claimed:

- Public-data ML ingestion, training, inference, dataset provenance, or metrics.
- Synthetic FinGuard dataset generation, leakage detection, or LoRA/QLoRA fine-tuning.
- LLM-driven adaptive red-team loop and measured attack-success/block rates.
- Cryptographically signed policy artifacts; policy integrity is represented in
  receipts but existing policy files are not yet signed.
- Real bank/payment integrations, real funds, HSM/KMS, and a production ledger.

## Security conclusion

### Phase 2C local-AI update

The previously incomplete local-AI foundation is now connected to the bounded
treasury-agent path. `OllamaModel` calls the loopback Ollama API using the
installed `qwen3:0.6b` model; `LocalAIAnalyzer` requests JSON and validates
the amount, supported currency, explicit destination, purpose, confidence, and
bounded risk fields. Ambiguous destinations, malformed output, model failures,
and overlong prompts return clarification rather than creating a transaction.

The validated AI assessment is retained as advisory evidence in the decision
receipt. It cannot change the `DecisionEngine` result and still passes only
through the request-only `FinGuardAgentClient`; the signing gate remains the
sole route to a signature. `finguard agent status` now reports local runtime
and model availability.

Verification added: three runtime-independent tests cover valid structured
extraction, rejection of an ambiguous destination, and model-failure handling.
They passed together with the Phase 2 decision tests (6 passed). A first live
Ollama request showed that cold model startup exceeds the prior 60-second
client timeout, so the adapter timeout is now 180 seconds. Do not treat the
model's output as fraud scoring or autonomous authorization.

### Phase 2B security-core update

The final application signing route is now `SigningGate`. It rejects requests
without a DecisionEngine receipt and rechecks the stored/canonical transaction
hash, signed identity and actor type, authority, current policy version/hash,
deterministic risk/policy outcome, approval integrity, and nonce ownership
before unlocking a keystore key and invoking Ed25519.

Approvals now sign a canonical payload containing transaction hash, request ID,
approver ID, approval type, policy version/hash, timestamp, and a 30-minute
expiry. They cannot be used by the requester or against a different
transaction, and policy/transaction drift invalidates them.

Verification at the Phase 2B checkpoint: **33 tests passed**. This includes new direct-gate rejection,
agent self-approval, mutation, approval theft, policy-modification, replay,
and concurrent replay tests. A local LLM was not configured: an RTX 3050 6 GB
GPU was detected, but no local inference runtime was installed and RAM/disk
queries were denied by the sandbox.

The delivered product-first implementation materially improves the
authorization architecture for agent requests and adds local virtual
settlement. It remains a local research prototype, not production banking
infrastructure, and does not move real money.
