# FIN//GUARD Threat Model & Security Architecture

## 1. Central Security Thesis

FinGuard assumes its primary adversary is **not** a traditional human hacker with stolen password credentials, but an **autonomous AI agent** (compromised, prompt-injected, jailbroken, or simply misinstructed) that possesses legitimate API/tool-calling credentials to request financial transactions.

The central security question FIN//GUARD investigates is:
> *Can an autonomous AI agent, by a sequence of tool calls or parameter manipulation, cause an unauthorized synthetic transfer to be authorized or executed?*

The current implementation applies deterministic identity, authority, policy,
replay, approval, signing, and simulator checks on its implemented local
CLI/SDK path. The decision/approval/signing/execution chain now carries the
canonical v2 transaction hash and persisted lifecycle-version evidence; approval
and signer keys must match public keys in the root-signed identity registry.
This is not a proof of a universal **NO**. Decision, approval, signing, and
synthetic execution writes use local SQLite transaction boundaries that include
their required database evidence; deterministic injected failures and
separate-session thread tests exercise rollback, retry, and one-effect behavior.
Separate-OS-process signing and execution races are tested: exactly one signing
process stores a valid signature and one signing audit entry; competing
execution processes observe one stored result and produce one financial effect.
Injected failures across decision, approval, signing, and execution paths roll
back their partial writes; fresh-session reads and exact-operation retries
verify recovery. Abrupt process termination during commit remains untested.

M4 adds a bounded orchestrator around this path. The orchestrator is not
authority. It records state, budgets, tool observations, and guardrail checks,
but it cannot approve, sign, authorize, or mutate funds. Tool output is treated
as untrusted data only; it cannot alter capabilities, approval state, or
execution permission. Replanning is constrained to the original run budget and
boundaries.

No product MCP server exists, and claims must remain limited to behaviors with
passing tests and measured evaluation evidence.

---

## 2. Threat Actors & Boundaries

| Actor Type | ID / Scope | Trust Level | Capabilities & Controls |
| :--- | :--- | :--- | :--- |
| **`AGENT`** | Autonomous LLM / Tool-Calling Process | **UNTRUSTED** | Can ONLY invoke `finguard agent-request ...`. Cannot sign transactions, approve transactions, or modify identities. Subject to mandatory human approval floor. |
| **`HUMAN_OPERATOR`** | Human Security / Treasury Operator | **TRUSTED (Constrained)** | Can invoke full operator CLI; signing key must match this actor's public key in the root-signed registry. Cannot bypass policy or transaction CAS. |
| **`APPROVER`** | Designated Approver | **HIGH TRUST** | Can approve pending transactions only with the actor-bound registry key. Ed25519 approval binds transaction hash, request, policy identity, expiry, and target approved version. |
| **`ROOT_OPERATOR`** | Offline Root Authority | **ROOT TRUST** | Holds root operator key (`root_operator.key`) to re-sign identity & authority registry (`identities.yaml.sig`). |

---

## 3. Threat Vectors & Defense Mechanisms

### Threat Vector 1: Transaction Replay
- **Attack**: An attacker captures a valid signed transaction and attempts to submit or sign it again with the same nonce.
- **Scenario**: `finguard/attacks/scenarios/replay.yaml`
- **Mitigation**: Persistent SQLite `NonceStore` registers every used nonce; a new request reusing that nonce is blocked. An exact retry of an already completed simulator execution returns its original evidence-checked result and applies no additional financial effect. Both paths preserve the single-effect invariant.

### Threat Vector 2: Transaction Tampering In-Flight
- **Attack**: An attacker modifies the amount or parameters of a transaction after human approval but prior to final cryptographic signing.
- **Scenario**: `finguard/attacks/scenarios/tampering.yaml`
- **Mitigation**: Approvals bind the approver's Ed25519 signature directly to `transaction_hash = SHA-256(canonical_bytes)`. Modifying any transaction field changes the hash, causing approval verification to fail and blocking signing.

### Threat Vector 3: Privilege Escalation
- **Attack**: A low-privilege agent attempts to request a high-value transaction (e.g. ₹100,000) exceeding its declared limit (e.g. ₹10,000).
- **Scenario**: `finguard/attacks/scenarios/privilege_escalation.yaml`
- **Mitigation**: Authority limits are declared in `identities.yaml` and protected by a detached Ed25519 root signature (`identities.yaml.sig`). Attempts exceeding authority limits are blocked immediately by `PolicyEngine` and `RiskEngine` with `AUTHORITY_VIOLATION`.

### Threat Vector 4: Destination Manipulation
- **Attack**: An attacker or rogue agent redirects an approved vendor payment to an unapproved destination account.
- **Scenario**: `finguard/attacks/scenarios/destination_manipulation.yaml`
- **Mitigation**: Destination allowlists are checked against both signed `IdentityRegistry` and `PolicyConfig`. Post-approval destination changes invalidate the transaction hash.

---

## 4. Load-Bearing Cryptographic Invariants

1. **Deterministic Canonicalization**:
   $$H(T) = \text{SHA256}(\text{canonical\_serialize}(T))$$
   Sorted JSON keys, fixed-point decimal amounts (`1000.00`), explicit UTC ISO-8601 timestamps. Modifying any field invalidates $H(T)$.

2. **Agent Approval Floor**:
   $$\forall T \text{ where } \text{actor\_type}(T) = \text{AGENT} \implies \text{required\_approvals}(T) \ge 1$$
   Agents can NEVER self-authorize transactions under any policy configuration.

3. **Tamper-Evident Audit Chain**:
   $$E_n = \text{SHA256}(E_{n-1}.\text{hash} \parallel \text{timestamp} \parallel \text{actor} \parallel \text{action} \parallel \text{tx\_id} \parallel \text{result} \parallel \text{meta})$$
   `finguard audit verify` re-computes $E_1 \dots E_N$ to detect modified, deleted, or inserted historical entries.

4. **Signed Attestation Artifact**:
   `finguard attest generate` produces a signed `AttestationReport` JSON artifact signed by an Ed25519 attestor key, allowing third parties to independently verify ledger integrity via `finguard attest verify`.

   5. **Transaction Authority Chain**:
      - Transaction identity is the existing canonical v2 SHA-256 hash; no second transaction serializer is introduced.
      - The policy receipt records that hash and its lifecycle row version. Approval requests bind the same hash/version; approval signatures bind the prospective `APPROVED` row version and the signed-registry approver key.
      - Signing rechecks receipt, current policy/authority, approval evidence, signer registry key, and the exact row version being consumed; the signature remains over canonical v2 bytes. Its `signed_version` is recorded with the signature/key in a row-level CAS.
      - Execution revalidates receipt, decision audit, policy, authority, approval evidence when required, signer audit/key, canonical hash, and signature. Balance debit/credit, unique execution record, `SIGNED -> EXECUTED` CAS, and execution audit entry share one SQLite transaction. An exact completed retry returns the stored deterministic result after checking its evidence; it does not repeat the transfer.
      - Decision + nonce + optional approval request + lifecycle CAS + receipt + DECISION ledger entry share one SQLite transaction. Approval state/audit and signing CAS/signature/audit likewise share their write transaction. Injected failures roll these writes back; these are DB-local effects only. Execution acquires SQLite's writer reservation with `BEGIN IMMEDIATE` before reading transaction/evidence, and SQLite's 5-second `busy_timeout` lets a competing process wait and then observe the committed idempotent result. This lock is intentionally scoped to simulator execution, not applied to every transaction.
      - Lifecycle `version` is a database concurrency token, not an authority input: API callers do not supply it; SigningGate reads the authorized row version, CAS-writes SIGNED plus `signed_version`, and appends that version to signing evidence in the same transaction. Execution rejects unless row version equals `signed_version` and matching signing evidence is present. A test changes the signed row version and proves no transfer occurs. The signature intentionally remains over canonical v2 transaction bytes: adding lifecycle state to a signature envelope would change the signing contract without strengthening the binding of amount, accounts, metadata, or other execution authority data. M2.2 therefore does not claim the lifecycle counter is itself cryptographically signed. A privileged whole-file database writer can rewrite the row and recompute the co-located unkeyed audit chain; protection against that actor needs signed checkpoints/external anchoring and a separately G6-reviewed signing-envelope change, both outside this milestone.

---

## 5. Security Limitations & Operational Boundaries

- **Single-Machine Runtime**: The MVP operates as a local CLI tool and SQLite database. Distributed HSMs, MPC, and multi-region consensus are outside MVP scope.
- **Local Root Key Storage**: For demonstration purposes, `root_operator.key` is generated in `.finguard/`. In production, this key should reside on an air-gapped physical token or hardware security module.

## 6. M3.1 Structured Intent Boundary

The model/agent output is hostile proposal data, not authority. The SDK
converts it into a versioned `StructuredIntent` and sends it through bounded
JSON parsing, duplicate-field rejection, strict schema validation, exact-money
parsing, fixed action/capability checks, and a registry-bound active AGENT
identity check. The agent cannot choose its effective identity, transaction
timestamp, nonce, operation, approval, signer, signature, decision, lifecycle
state, or execution path. Its intent ID anchors replay identity; the nonce is
domain-separated and derived by the boundary from the bound actor and intent
ID.

The intent is normalized and domain-separated for its digest. Its digest and
fixed requested action/capability are embedded in transaction metadata, which
is covered by the existing canonical-v2 transaction hash. The existing
DecisionEngine, ApprovalService, SigningGate, simulator, and checkpointed
audit ledger remain authoritative. A proposal accepted by the intent boundary
is not an authorization event and cannot directly move balances.

The intent schema rejects malformed/ambiguous input, duplicate or unexpected
fields, unsupported action/capability, invalid identities, invalid exact
amounts, unresolved recipient placeholders, authority-like fields, and
oversized input/context. Descriptive reason/context strings are never
interpreted as instructions by this boundary. It does not claim to recognize
all natural-language prompt injection; its guarantee is that text cannot grant
authority or call an execution tool.

An exact replay reuses the stored transaction timestamp and must match the
stored intent digest, canonical transaction hash, transaction ID, idempotency
key, and nonce record. Conflicting intent-ID reuse is rejected; a
caller-supplied nonce is rejected, and distinct intent IDs derive distinct
nonces. Existing decision/simulator idempotency controls prevent a duplicate
financial effect. Intent receipt/accept/rejection events are
supplementary appends to the existing ledger; they do not replace the atomic
decision/receipt/ledger transaction.

M3.1 does not implement MCP, autonomous planning/loops, external model APIs,
general tool execution, or an injection classifier. External anchoring of
signed ledger checkpoints remains a separate future control.
