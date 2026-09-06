# Security model

## Central invariant

**The AI must never be the final authority over money.**

AI-generated intent, FinGuard authorization, cryptographic signing, and
financial execution are separate stages:

```text
AI-generated intent
	-> FinGuard authorization decision
	-> independent human approval when required
	-> cryptographic signing by SigningGate
	-> virtual financial execution by the simulator
```

The model may interpret a user request and propose transaction fields. Those
fields remain untrusted input. Even malicious model output is only a request
until it passes deterministic controls.

## Boundaries

`TreasuryAgent` calls only `FinGuardAgentClient`. The request SDK contains
request and inspection operations; it has no signing, private-key, approval,
policy mutation, identity mutation, audit mutation, decision override, or
simulator execution operation.

`DecisionEngine` independently validates signed identity, actor type, agent
source account, authority limit, destination allowlist, policy, deterministic
risk, session presence, and nonce uniqueness. It persists a canonical decision
receipt and audit event, failing closed on uncertainty.

`ApprovalService` binds human approval to the exact transaction hash, request,
policy, and approval signature. `SigningGate` is the only application signing
route and revalidates the receipt, identity, policy, authority, risk, approval,
nonce, and transaction hash immediately before signing.

`FinancialSimulator` is not an AI tool. It independently requires a stored
`SigningGate` signature, verifies the canonical transaction hash and signature,
and settles a transaction once into virtual accounts.

## Trust assumptions and scope

The model, user prompt, local Ollama output, and agent request are untrusted.
The implementation assumes the host, Python runtime, configured trust keys, and
cryptographic primitives have not been compromised. The measured result is
scoped to the tested FinGuard execution path, local simulator, Ollama/Qwen
configuration, and fixed adversarial attack corpus.
