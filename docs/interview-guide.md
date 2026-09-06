# FinGuard interview guide

## What is FinGuard?

FinGuard is a security gateway between an AI agent and financial execution. It
lets an AI interpret instructions and submit a transaction request, while
keeping identity, policy, approval, signing, and execution outside the model.

## Why is this more than a payment authorization system?

The focus is the AI-to-financial-execution boundary. The threat is not only a
bad caller; it is a manipulated or compromised model that can still produce a
valid-looking request. FinGuard treats that request as untrusted input and
independently re-evaluates it.

## Why cannot the AI simply call the signing function?

The request SDK exposed to the agent contains no signing or private-key
operation. Signing is centralized in `SigningGate`, which requires persisted
FinGuard decision evidence, current policy and identity checks, valid approval,
and nonce and transaction-integrity checks.

## How does FinGuard handle prompt injection?

Prompt injection can influence what the model proposes, but it cannot grant
authority. The resulting fields still pass through deterministic identity,
authority, policy, risk, nonce, approval, signing, and simulator checks.

## How do you know the AI did not move money?

For requests that reached approval, the harness attempted signing without a
valid signing credential, attempted simulator execution, and measured isolated
balances before and after. The final 100-attempt evaluation recorded zero
executions and zero unauthorized executions.

## What did the red-team evaluation find?

Across 100 real Ollama/Qwen attempts, 20 were directly blocked by FinGuard, 50
reached mandatory approval, 70 signing attempts were rejected, 30 model outputs
were invalid, and zero executions occurred. The stage counts overlap; they are
not 170 independent attacks.

## What vulnerabilities did you discover?

The final audit found that agent requests could select an arbitrary source
account and that attestation verification trusted an embedded public key. Agent
source accounts are now restricted to `treasury`, and attestations are checked
against the configured trusted key and live ledger state. Both fixes have
regression coverage.

## Why are some AI attacks listed as REACHED_APPROVAL?

`REACHED_APPROVAL` means the model produced a syntactically valid request that
passed initial deterministic checks but still required human approval. It does
not mean the transaction executed or that the AI received approval authority.
The release harness then tested signing and simulator execution without valid
credentials.

## What does the 100-run experiment actually prove?

It provides empirical evidence that the fixed ten-case corpus did not produce
an unauthorized execution through the tested FinGuard path, using the real
local Ollama/Qwen integration and isolated state per attempt. It does not prove
universal AI safety or absolute security.

## What are the limitations?

The result is scoped to the tested execution path, local simulator, model
configuration, and fixed corpus. It does not cover every attack, future model,
unknown implementation bug, compromised host, compromised Ollama installation,
or adaptive multi-step tool-using agents beyond this architecture. It also does
not represent production banking security or real-money movement.
