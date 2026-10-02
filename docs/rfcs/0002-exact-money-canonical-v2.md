# RFC 0002: Exact Money and Canonical Transaction v2

- **Status:** Implemented locally; security approval pending
- **Scope:** FG-201 / FG-202 exact money, canonical bytes, legacy verification
- **Compatibility:** Read-only legacy v1 verification; new decisions/signatures use v2

## Context

The prior transaction model accepted floats and canonical v1 rounded amounts to
two decimal places. A positive amount below one cent could therefore share the
same signed representation as zero, while policy and simulator calculations
used the unrounded value. The signed field set also needed an explicit version
and domain boundary.

## Decision

Represent authoritative money as immutable integer minor units plus a supported
currency. Parse external amounts only from integers, strings, or `Decimal`
values using a strict ASCII decimal grammar. Reject floats, booleans, non-finite
values, unsupported currencies, excess precision, non-positive values, and
amounts above the documented cap.

New transactions use canonical v2. Its preimage is the exact domain prefix
`b"finguard.tx.v2\x00"` followed by sorted compact JSON containing
`canonical_version`, `amount_minor`, `currency`, the signed transaction
fields, and metadata digest. A v2-specific timestamp encoder normalizes aware
datetimes to UTC. The v1 encoder is preserved separately for historical byte
compatibility.

## Alternatives

1. Keep float as the transaction field and use Decimal only at serialization.
   Rejected: comparisons and execution can still observe a different value.
2. Accept float only when it appears to have two decimal places. Rejected:
   the source value was already rounded to binary and JSON/type boundaries vary.
3. Use decimal strings throughout every internal calculation. Rejected:
   comparisons, arithmetic, and simulator conservation are simpler to establish
   over integer minor units.
4. Replace the whole legacy SQLite table in this ticket. Deferred: it requires a
   separately reviewed backup, exactness audit, quarantine report, rollback,
   and populated-schema migration suite. Additive columns are introduced, but
   old float rows are not silently backfilled.

## Security Review Notes

- Reproduced and rejected float/sub-cent, NaN/Infinity, bool-as-int,
  unsupported-currency, malformed decimal, mutable Money, and v1 creation
  attempts.
- Added an attack test where transaction and receipt rows are edited together;
  signing now checks receipt hash correspondence to a valid decision ledger
  entry.
- The audit chain is stored in the same SQLite database and is not protected by
  a signed checkpoint in this milestone. A database writer able to rewrite the
  full chain can recompute its unkeyed hashes. This change therefore does not
  claim protection against a fully privileged database-file attacker. M2 must
  add signed checkpoints/external anchoring and concurrency/fault guarantees.
- Exact backfill/quarantine and actual pre-change populated-database v1
  verification remain unproven.
- Independent verifier sign-off and human approval are still required before
  merge/push because authenticated canonical bytes changed.

## Consequences

V2 decisions, receipts, signing, and simulator settlement share the same
minor-unit amount. Existing v1 records remain distinguishable and cannot be
signed or executed. Existing float columns remain legacy compatibility data;
new policy, authorization, hashing, approval, and execution paths must not read
them as authoritative values.