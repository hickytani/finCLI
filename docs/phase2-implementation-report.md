# FinGuard Phase 2 implementation report

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
| Honest model fallback | The agent is explicitly a deterministic parser with `model=not-configured`; it is not represented as LLM inference. |
| Red-team harness | Added `RedTeamRunner`, which uses the real SDK for authority-escalation attempts and records forbidden-tool attempts. It does not claim adaptive LLM attacks. |
| Replay hardening | Updated `NonceStore.record` to attempt an atomic database insert and return `False` when a duplicate nonce wins the race. |
| Tests | Added three Phase 2 tests for authority hard-blocking, unknown-identity fail-closed behavior, and absence of SDK signing/self-approval methods. |
| Documentation | Added README and architecture, security, threat, model, dataset, reality-matrix, red-team, repository-audit, and this implementation-report documents. |

## Verification performed

`python -m pytest -q -p no:cacheprovider --basetemp .\\test-tmp4`

Result: **26 passed**. The test command used a workspace-local temporary
directory because the environment denied access to the existing Windows pytest
temporary/cache directory. Temporary verification directories were removed.

## Current limitations / not completed

The following were not implemented or measured, and are not claimed:

- Local open-weight LLM inference or structured LLM output validation.
- Public-data ML ingestion, training, inference, dataset provenance, or metrics.
- Synthetic FinGuard dataset generation, leakage detection, or LoRA/QLoRA fine-tuning.
- Local execution simulator and account balances.
- LLM-driven adaptive red-team loop and measured attack-success/block rates.
- Full signing-gate revalidation through the new DecisionEngine. The pre-existing
  CLI signer remains and needs a further hardening pass to recheck current
  identity, policy integrity/version/hash, approvals, nonce, and security state
  immediately before signing.
- Approval cryptographic binding to policy version, request ID, approval type,
  and explicit expiry checks.
- Cryptographically signed policy artifacts; policy integrity is represented in
  receipts but existing policy files are not yet signed.

## Security conclusion

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

Verification: **33 tests passed**. This includes new direct-gate rejection,
agent self-approval, mutation, approval theft, policy-modification, replay,
and concurrent replay tests. A local LLM was not configured: an RTX 3050 6 GB
GPU was detected, but no local inference runtime was installed and RAM/disk
queries were denied by the sandbox.

The delivered change materially improves the authorization architecture for
new CLI/SDK agent requests: the agent is constrained to a request-only SDK and
the same central engine produces the decision and its evidence. It is a local
research prototype, not production banking infrastructure, and does not move
real money.
