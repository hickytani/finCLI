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
separate-session thread/process tests exercise rollback, retry, and one-effect
behavior. Separate-OS-process signing and execution races are tested: exactly
one signing process stores a valid signature and one signing audit entry;
competing execution processes observe one stored result and produce one
financial effect. Injected failures across decision, approval, signing, and
execution paths roll back their partial writes; fresh-session reads and
exact-operation retries verify recovery. Abrupt process termination during
commit remains untested.
Signatures cover canonical v2 transaction bytes but do not directly include the
database lifecycle-version counter. That counter is not request-supplied
authority data: it is a persistence CAS token, checked against the versioned
decision/approval/signing evidence and current row before execution. This
protects against stale lifecycle state when the linked evidence is unchanged,
but is not cryptographic protection against an attacker who can rewrite the
entire SQLite file and recompute its uncheckpointed hash chain. Binding the
counter into a signed envelope would change the signing contract and requires
separate G6 review; it is intentionally outside M2.2. The audit ledger now has
monotonic sequence numbers and identity-key-bound Ed25519 checkpoints over
canonical ledger prefixes. Checkpoints are explicit/on-demand and stored in the
same SQLite database: entries after the latest checkpoint remain unsigned, and
without an external anchor an attacker able to rewrite the database can truncate
history to an earlier valid checkpoint. No product MCP server exists.

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
   `seq` is checked for contiguous order separately from the entry hash. Signed
   checkpoints bind the declared sequence and ledger head; they detect changes
   within a covered prefix. Entries newer than the latest explicit checkpoint
   are not checkpoint-covered, and there is no external anchor to prevent
   rollback to an earlier valid checkpoint.

4. **Signed Attestation Artifact**:
   `finguard attest generate` produces a signed `AttestationReport` JSON artifact signed by an Ed25519 attestor key, allowing third parties to independently verify ledger integrity via `finguard attest verify`.

   5. **Transaction Authority Chain**:
      - Transaction identity is the existing canonical v2 SHA-256 hash; no second transaction serializer is introduced.
      - The policy receipt records that hash and its lifecycle row version. Approval requests bind the same hash/version; approval signatures bind the prospective `APPROVED` row version and the signed-registry approver key.
      - Signing rechecks receipt, current policy/authority, approval evidence, signer registry key, and the exact row version being consumed; the signature remains over canonical v2 bytes. Its `signed_version` is recorded with the signature/key in a row-level CAS.
      - Execution revalidates receipt, decision audit, policy, authority, approval evidence when required, signer audit/key, canonical hash, and signature. Balance debit/credit, unique execution record, `SIGNED -> EXECUTED` CAS, and execution audit entry share one SQLite transaction. An exact completed retry returns the stored deterministic result after checking its evidence; it does not repeat the transfer.
      - Decision + nonce + optional approval request + lifecycle CAS + receipt + DECISION ledger entry share one SQLite transaction. Approval state/audit and signing CAS/signature/audit likewise share their write transaction. Injected failures roll these writes back; these are DB-local effects only. Execution acquires SQLite's writer reservation with `BEGIN IMMEDIATE` before reading transaction/evidence, and SQLite's 5-second `busy_timeout` lets a competing process wait and then observe the committed idempotent result. This lock is intentionally scoped to simulator execution, not applied to every transaction.
      - Lifecycle `version` is a database concurrency token, not an authority input: API callers do not supply it; SigningGate reads the authorized row version, CAS-writes SIGNED plus `signed_version`, and appends that version to signing evidence in the same transaction. Execution rejects unless row version equals `signed_version` and matching signing evidence is present. A test changes the signed row version and proves no transfer occurs. The signature intentionally remains over canonical v2 transaction bytes: adding lifecycle state to a signature envelope would change the signing contract without strengthening the binding of amount, accounts, metadata, or other execution authority data. M2.2 therefore does not claim the lifecycle counter is itself cryptographically signed. M2.3 checkpoints prevent undetected rewriting of covered prefixes without the identity-bound signing key, but the co-located database can still be truncated to an earlier valid checkpoint without external anchoring; lifecycle-envelope binding remains a separate G6-reviewed change.

---

## 5. Security Limitations & Operational Boundaries

- **Single-Machine Runtime**: The MVP operates as a local CLI tool and SQLite database. Distributed HSMs, MPC, and multi-region consensus are outside MVP scope.
- **Local Root Key Storage**: For demonstration purposes, `root_operator.key` is generated in `.finguard/`. In production, this key should reside on an air-gapped physical token or hardware security module.

## 6. M3 Local AI/Agent Boundary

- Model output is parsed into a strict extraction schema with extra fields
  forbidden. The model supplies amount, currency, destination, purpose, and
  advisory analysis only; actor identity, source account, timestamp, nonce,
  idempotency key, policy, decision, approval, signature, and lifecycle state
  are server/core-controlled.
- The local `AgentSecurityBoundary` accepts one proposal capability per turn.
  It resolves identity and source grants from the root-signed registry and
  delegates authorization to the existing `DecisionEngine`. Agent transactions
  still require the existing human approval, SigningGate, and simulator checks.
  The boundary has no signing, approval, key, policy-mutation, or execution
  operation.
- A future `AgentToolTransport` can carry one fixed, typed proposal call. Its
  response is untrusted data: unknown fields, oversized payloads, mismatched
  transaction/receipt data, or altered persisted transaction fields are
  rejected. The current implementation uses the in-process core adapter; it
  does not implement a product MCP server or claim remote MCP isolation.
- Each turn is limited to one extraction iteration and one proposal call, with
  request/intent/result size bounds, elapsed-time and tool-call timeouts, an
  optional value ceiling, and cancellation checks. A timeout or cancellation
  after dispatch is outcome-unknown and returns a reconciliation state; a
  blocking worker may continue. The proposal capability cannot sign or settle
  money, and the boundary does not automatically retry an ambiguous outcome.
- Prompt and tool-result injection are not controlled by prompt wording. The
  security boundary is strict parsing, server-bound identity/capability,
  deterministic authority/policy, mandatory human approval for agents, and
  existing cryptographic execution checks. The adversarial tests use fixed
  model/tool doubles and do not establish model accuracy or external MCP
  security.
