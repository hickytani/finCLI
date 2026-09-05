# Phase 2 repository audit

| Component | Current implementation | Reusable | Required change / concern | Tests |
|---|---|---|---|---|
| Identity | Signed YAML registry with Ed25519 root signature | Yes | Fail closed on registry failure | identity registry |
| Crypto/keystore | Ed25519, AES-GCM, Argon2id | Yes | Keep keys outside agent SDK | signing, keystore |
| Transaction | Canonical hash includes core security fields | Yes | Preserve metadata on persistence/reconstruction review | canonical |
| Policy/risk | YAML policy and deterministic signals | Yes | Centralize invocation | policy engine |
| Approvals | Hash-bound records | Partly | Bind policy/request metadata and stale-expiry in next hardening pass | policy tests only |
| Replay | SQLite unique nonce | Yes | Atomic insert now used by DecisionEngine | decision tests |
| Audit | Hash-chained SQLite ledger | Yes | Agent/red-team decision events added | audit ledger |
| CLI/agent request | Separate duplicated authorization flows | No | Redirected creation to DecisionEngine | phase2 decision |
| Attacks | Declarative scenario loader | Yes | Add adaptive model runner when local model is available | attack scenarios |
| ML/LLM | Not present | No | Documented limitation; no fabricated model/data claims | not measured |

The legacy transaction signing command still requires a Phase 2 revalidation
refactor; it is not exposed by the agent SDK.
