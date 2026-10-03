# RFC 0001: Cryptographic Binding of Transaction Metadata Digest in Canonical v2

- **Author**: FIN//GUARD Security Architecture Team
- **Date**: 2026-10-02
- **Status**: APPROVED / IMPLEMENTED IN CANONICAL V2
- **Impact**: Security Boundary, Canonical Form v2, Signature Binding

---

## 1. Context & Threat Model

In canonical serialization v1, `Transaction.canonical_fields()` included:
`transaction_id`, `actor_id`, `session_id`, `from_account`, `to_account`, `amount`, `currency`, `nonce`, `timestamp`, `idempotency_key`, `policy_version`.

However, the `metadata` dictionary (which stores application-level context such as `purpose`, `invoice_id`, or `remittance_details`) was **excluded** from the canonical signed fields.

### Security Vulnerability (FG-206)
1. **Metadata Tampering / Approver Deception**: An attacker submits a transaction for approval with metadata `{"purpose": "Vendor Payroll"}`.
2. The human approver or policy rule inspects the purpose and approves the transaction hash.
3. After approval but before final signing/settlement, an attacker or compromised intermediate component alters `metadata` to `{"purpose": "Ransomware Extortion"}`.
4. Because `metadata` was excluded from canonical v1 bytes, the signed transaction hash remained unchanged (`tx1.transaction_hash() == tx2.transaction_hash()`), permitting execution of a transaction whose purpose was silently substituted.

---

## 2. Decision & Technical Specification

In Canonical Serialization v2:
1. `metadata_digest` is added as a mandatory field in `canonical_fields(version=2)`.
2. `metadata_digest = SHA-256(UTF-8(json.dumps(metadata, sort_keys=True, separators=(",", ":"))))` if metadata is non-empty, or `SHA-256(b"")` if metadata is null/empty.
3. Any post-approval mutation of `metadata` changes `metadata_digest`, invalidates the canonical v2 preimage, and causes signature verification to **FAIL CLOSED** (`IntegrityError`).

---

## 3. Alternatives Considered

1. **Option A: Embed full raw metadata dictionary directly into canonical JSON fields**.
   - *Rejected*: Raw metadata dictionaries contain arbitrary nested keys, dynamic whitespace, or non-deterministic order, creating canonical serialization fragility across different programming languages or clients.
2. **Option B: Hash metadata separately into a metadata_digest field (SELECTED)**.
   - *Accepted*: Binds metadata deterministically with a fixed 64-character SHA-256 hex string, preserving clean schema boundaries while securing metadata against post-approval tampering.

---

## 4. Migration & Backward Compatibility

- Existing v1 signatures remain verifiable via frozen `canonical_serialize_v1()` (read-only verification path).
- All new transactions generated under Milestone M1 output `canonical_version: 2` with `metadata_digest` bound to `finguard.tx.v2\x00` domain-separated canonical bytes.
