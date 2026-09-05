# FIN//GUARD

CLI-first research prototype for cryptographically bounded financial-agent requests.
It uses a local execution model only: **NO REAL MONEY IS MOVED**.

## Implemented

Phase 2B provides `DecisionEngine` plus a final `SigningGate`: new CLI/SDK
requests are decided centrally, and application signing revalidates the receipt,
identity, authority, current policy hash/version, risk, approval, nonce, and
transaction hash immediately before Ed25519 signing. `FinGuardAgentClient` is
request-only; it cannot sign, approve, alter policy, or obtain private keys.

## Not yet implemented

There is no configured local LLM, ML dataset/model, LoRA/QLoRA training, or
local execution simulator. The treasury parser is not represented as LLM
inference. This project is a local research prototype: **NO REAL MONEY IS
MOVED**.

Run `finguard init`, then `finguard agent-request tx-create --from treasury --to vendor-a --amount 8500`.

See [architecture](docs/architecture.md), [security model](docs/security-model.md), and the [reality matrix](docs/reality-matrix.md).
