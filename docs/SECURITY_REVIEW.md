# Security Review Record

## FG-201 / FG-202: Exact Money and Canonical v2

- **Review state:** Pending independent verifier and human approval
- **Implementation branch:** `m1-money`
- **Starting commit:** `5d9ac23`
- **Review date:** 2026-10-02

### Confirmed defenses

- Positive amounts use integer minor units and explicit currency exponents.
- New transaction amount parsing rejects float, bool, non-finite, excess
  precision, unsupported currency, and ambiguous decimal syntax.
- Canonical v2 includes amount minor units, currency, metadata digest, version,
  and domain prefix; v1 uses a separate compatibility encoder.
- Decision receipt digest is matched to its decision audit evidence and the
  audit hash chain is verified before signing.
- Idempotency key, policy version, and metadata survive persistence and
  reconstruction through decision, signature, and execution.
- Transaction timestamps normalize to aware UTC at construction, avoiding
  offset loss when SQLite stores its naive `DateTime` representation.
- Signed actor authority now carries an explicit currency; decision, policy,
  risk, and signing checks reject mismatches instead of comparing raw minor
  unit integers across currencies.
- The signed registry's `allowed_source_accounts` field is now loaded into the
  actor model; empty source/destination/action grants deny, and agent wildcards
  (including literal `*` account requests) are rejected.
- Actor authority limits carry an explicit currency and decision, policy, risk,
  helper, and signing paths reject currency mismatches instead of comparing
  minor-unit integers across currencies.
- A dry-run/apply legacy money migration exists. Its fixture suite exercises
  exact, inexact, and non-finite stored floats, backup-required apply, quarantine,
  unsigned-request failure, dry-run immutability, and idempotence.

### Residual risks and evidence gaps

- Audit rows and their hash chain are in the same database and unsigned here;
  a writer able to rewrite the whole database can recompute the chain. M2
  signed checkpoints and external anchoring remain necessary.
- The coordinated transaction/receipt row-edit regression leaves the audit
  row untouched. A whole-database attacker can still rewrite the audit entry
  and recompute the unkeyed chain; this gate is not an independent trust anchor.
- Legacy float exactness audit, quarantine, backup, rollback, and migration
  reporting are now implemented in code and fixture-tested, but the migration
  has not been run on the operator DB or a complete production-shaped legacy DB;
  backup restore and rollback drills remain unverified.
- CLI verification of a real signed v1 artifact from a pre-change database is
  not yet exercised end-to-end.
- Full suite has three previously existing failures in
  `test_redteam_hardening_pass.py`; repository Ruff gate remains non-green.
- The independent follow-up review found and the implementation addressed
  optional-field persistence and offset-timestamp round-trip issues. The
  focused canonical/signing/simulator tests pass after those changes.
- A registry-backed Account table and alias/currency validation remain absent;
  actor source/destination lists are the current authorization granularity.

### Approval

- Independent verifier: **PENDING**
- Human owner canonicalization approval: **PENDING**
- Push/merge authorization: **PENDING**