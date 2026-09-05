# FinGuard product-gap report

## Plain-language product test

FinGuard is a checkpoint between an AI worker and a money-moving system. It
lets the worker propose a payment, but independently decides whether the
payment may be approved, signed, and executed.

Ordinary payment-API permissions give a credential broad standing authority.
FinGuard adds an action-time boundary: signed agent identity, per-action limits
and destination controls, deterministic policy/risk evaluation, human approval
bound to the exact request, replay protection, final signing revalidation, and
audit evidence. If an agent is compromised or prompt-injected, it can still
submit a request; it cannot make the independent boundary authorize it.

Unknown identity, malformed input, failed AI analysis, policy drift, stale or
mismatched approval, replay, and signing/execution failures are blocked.

## What already works

| Product control | Existing implementation |
|---|---|
| Agent has request-only access | `FinGuardAgentClient` exposes request/inspect/status only. |
| Independent authorization | `DecisionEngine` evaluates signed identity, authority, policy, deterministic risk, and nonce claim. |
| Human approval | Approval signatures bind transaction hash, request, approver, policy hash/version, and expiry. |
| Final execution authorization | `SigningGate` revalidates transaction, receipt, identity, policy, approval, and nonce immediately before signing. |
| Evidence | Hash-chained audit ledger, receipts, incidents, and attestation. |
| Local AI | Ollama/Qwen structured extraction is validated and advisory only. |

## Product gaps found before this rebuild

1. There was no FinGuard-controlled financial endpoint after signing, so no
   observable end-to-end money-movement demonstration existed.
2. There was no execution-time simulator guard against duplicate execution,
   invalid signatures, missing accounts, or insufficient synthetic funds.
3. Documentation was organized around implementation phases rather than the
   user-facing product flow.
4. The default agent limit is ₹10,000, whereas the brief's normal-demo example
   is ₹50,000. Raising it merely to satisfy a demo would weaken the shipped
   default; the normal flow therefore demonstrates required human approval at
   a permitted amount, and a deployment can explicitly configure its own cap.

## Scope decision

The minimum credible product increment is a local, atomic financial simulator
that only executes a FinGuard-signed, unexecuted transaction after verifying
the stored canonical transaction and Ed25519 signature. It must not be a
general balance-editing API available to the AI.

## Honest differentiation

Payment authorization, workflow approvals, transaction monitoring, cryptographic
signing, and AI-agent gateways are established categories. FinGuard does not
claim to invent them. Its specific local-first implementation combines a
request-only AI interface with transaction-bound approval, final signing
revalidation, and simulated financial execution, making the boundary directly
demonstrable. General-purpose agent gateways and payment platforms already
offer overlapping controls; FinGuard's value is this narrow, inspectable
financial-action boundary rather than novelty claims.

The landscape already includes general agent tool guardrails, agent identity/
authorization initiatives, and financial-agent authorization offerings. See
[OpenAI Agents tool guardrails](https://openai.github.io/openai-agents-js/guides/guardrails/),
[NIST's agent identity and authorization concept paper](https://www.nccoe.nist.gov/sites/default/files/2026-02/accelerating-the-adoption-of-software-and-ai-agent-identity-and-authorization-concept-paper.pdf),
and [an example financial-agent authorization product](https://axiru.com/ai-agents).

## Remaining limitations

This is a local prototype, not a banking integration. Its SQLite database is
not encrypted at rest; the local process and its keystore passphrases remain
trusted. It has no real payment rail, KMS/HSM, remote identity provider,
production policy administration, or measured fraud-model performance.
