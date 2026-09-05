# Phase 2 threat model

| Threat | Defense | Residual risk |
|---|---|---|
| Prompt injection/tool abuse | Small allowlisted SDK surface; forbidden operations absent | Model can still request permitted payments |
| Authority escalation | Signed registry + hard authority block | Root key compromise |
| Destination manipulation | Destination is identity/policy checked and hash-bound | Allowlist administration |
| Replay | SQLite unique nonce inserted atomically | Single-host SQLite availability |
| Stale/mutated approval | Transaction hash binding | Policy-version binding needs completion |
| Context poisoning/hallucination | Advisory context cannot authorize | Wrong request can reach approval queue |
| Policy tampering | Existing policy validation; signed policy integrity pending | Local policy files are not signed |
| Model supply chain | No model is bundled | Operator must verify any future model |
