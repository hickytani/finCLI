# FIN//GUARD Threat Model & Security Architecture

## 1. Central Security Thesis

FinGuard assumes its primary adversary is **not** a traditional human hacker with stolen password credentials, but an **autonomous AI agent** (compromised, prompt-injected, jailbroken, or simply misinstructed) that possesses legitimate API/tool-calling credentials to request financial transactions.

The central security question FinGuard answers is:
> *Can an autonomous AI agent, by any sequence of tool calls or parameter manipulation, cause funds to be cryptographically authorized without an independently verifiable, cryptographically bound human decision in the loop?*

FinGuard enforces a provable **NO**.

---

## 2. Threat Actors & Boundaries

| Actor Type | ID / Scope | Trust Level | Capabilities & Controls |
| :--- | :--- | :--- | :--- |
| **`AGENT`** | Autonomous LLM / Tool-Calling Process | **UNTRUSTED** | Can ONLY invoke `finguard agent-request ...`. Cannot sign transactions, approve transactions, or modify identities. Subject to mandatory human approval floor. |
| **`HUMAN_OPERATOR`** | Human Security / Treasury Operator | **TRUSTED (Constrained)** | Can invoke full operator CLI, sign transactions within authority limits, approve agent requests. Cannot bypass policy or tampering detection. |
| **`APPROVER`** | Designated Approver | **HIGH TRUST** | Can cryptographically approve pending transactions. Approval binds Ed25519 signature to `transaction_hash`. |
| **`ROOT_OPERATOR`** | Offline Root Authority | **ROOT TRUST** | Holds root operator key (`root_operator.key`) to re-sign identity & authority registry (`identities.yaml.sig`). |

---

## 3. Threat Vectors & Defense Mechanisms

### Threat Vector 1: Transaction Replay
- **Attack**: An attacker captures a valid signed transaction and attempts to submit or sign it again with the same nonce.
- **Scenario**: `finguard/attacks/scenarios/replay.yaml`
- **Mitigation**: Persistent SQLite `NonceStore` registers every used nonce. Re-attempts are immediately blocked, logged to audit ledger, and generate a `CRITICAL` security incident (`INC-XXXX`).

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

---

## 5. Security Limitations & Operational Boundaries

- **Single-Machine Runtime**: The MVP operates as a local CLI tool and SQLite database. Distributed HSMs, MPC, and multi-region consensus are outside MVP scope.
- **Local Root Key Storage**: For demonstration purposes, `root_operator.key` is generated in `.finguard/`. In production, this key should reside on an air-gapped physical token or hardware security module.
