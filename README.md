# FIN//GUARD

FinGuard is a local-first security gateway between AI agents and financial
actions. An AI can interpret and request a payment; it never receives authority
to approve, sign, or execute one. **NO REAL MONEY IS MOVED.**

## Implemented

Phase 2B provides `DecisionEngine` plus a final `SigningGate`: new CLI/SDK
requests are decided centrally, and application signing revalidates the receipt,
identity, authority, current policy hash/version, risk, approval, nonce, and
transaction hash immediately before Ed25519 signing. `FinGuardAgentClient` is
request-only; it cannot sign, approve, alter policy, or obtain private keys.

## Product flow

`AI request -> DecisionEngine -> human approval when required -> SigningGate -> local simulator -> audit evidence`

The local simulator holds only virtual INR balances. It independently requires
a valid stored FinGuard signature and canonical transaction hash, settles a
transaction once, and records the result in the audit ledger.

## Current limits

The bounded treasury agent can use a locally running Ollama model (`qwen3:0.6b`)
for strict JSON extraction and advisory risk signals. Model output is validated
and cannot approve, sign, alter policies/identities, or override deterministic
controls. There is no fraud-ML dataset/model, LoRA/QLoRA training, bank API,
HSM/KMS, or real-payment integration. This project is a local research
prototype: **NO REAL MONEY IS MOVED**.

Run `finguard init`, then `finguard agent-request tx-create --from treasury --to vendor-a --amount 8500`.
For local AI, ensure Ollama is running and run `finguard agent status`, then
`finguard agent run "Pay vendor-a INR 5000 for invoice 4471"`.

See the [product gap report](docs/product-gap-report.md), [two-minute demo](docs/product-demo.md), [security model](docs/security-model.md), and [reality matrix](docs/reality-matrix.md).
