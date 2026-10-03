# FIN//GUARD AGENT LOG

## Session Start: 2026-10-02

### Step 1: Baseline Verification
- Workspace: `c:\Users\prasu\Downloads\ftech`
- Virtual Environment: `.venv` (Python 3.13)
- Pytest Run: 128 tests total (123 PASSED, 5 FAILED in `test_redteam_hardening_pass.py`).
- Statements Coverage: 68% overall statement coverage (3790 statements, 1216 missed).
- Ruff Linter Run: 316 lint issues found (mostly unused imports, import ordering, and Exception handling in `test_redteam_hardening_pass.py` and `test_signing.py`).

#### Baseline Discrepancies & Findings:
1. Baseline test suite has 128 total tests. 123 pass. The 5 failing tests are in `tests/unit/test_redteam_hardening_pass.py` and directly demonstrate Appendix A vulnerabilities (Maker-Checker self approval / duplicate approval non-enforcement, transaction replay fail-closed message mismatch, incident invalid state transition handling, and audit ledger hash chain tamper verification).
2. Code coverage: 68% statement coverage.
3. Ruff check found 316 style/import lint errors.

### Step 5: Baseline Performance Measurements (`scripts/bench.py`)
- **Decision Pipeline Latency (sequential, SQLite WAL)**:
  - Throughput: `89.0 ops/sec` (Target: >= 50 ops/s) - **PASS**
  - p50 Latency: `9.88 ms` (Target: <= 15 ms) - **PASS**
  - p95 Latency: `19.40 ms` (Target: <= 50 ms) - **PASS**
  - p99 Latency: `39.64 ms`
- **Keystore Unlock Latency (Argon2id KDF)**:
  - p50 Latency: `231.64 ms`
- **Audit Ledger Verification**:
  - 200 Entries Verification Time: `184.61 ms` (Valid: True)

---

## M1 / FG-201 + FG-202 Implementation (2026-10-02)

### Starting State
- Branch/commit: `m1-money`, `5d9ac23` (`feat(m0): mission control setup, devtools mcp, Makefile, and defect proof suite`).
- Worktree already had uncommitted M1 edits; preserved and built on them.
- Full baseline run on that worktree: 146 passed, 7 failed. The 3 red-team-hardening failures repeated after M1 work; other baseline failures were subsequently fixed as amount-contract consumers were converted.

### M1 Changes
- Added immutable `Money` with strict decimal grammar, explicit INR/USD/EUR/JPY/KWD exponent table, bounded amount, exact minor-unit arithmetic, and float/bool/unsupported-currency rejection.
- `Transaction.amount` is now authoritative `Money`; new transaction version is frozen to v2. v2 bytes include the domain prefix, integer minor units, currency, metadata digest, and validated NFC identifiers.
- Decision, approval, signing, simulator, policy, AI extraction, SDK/CLI request, search, risk velocity, and forensic paths now use exact values; simulator balances expose minor units.
- Existing SQLite tables receive `amount_minor` and `canonical_version` columns; old rows default to v1. Legacy rows cannot be signed or executed. New rows write a Decimal-derived display shadow to the old Float column for older NOT NULL schemas; all v2 security controls use `amount_minor` only.
- Added frozen v1 bytes, hostile-input/property tests, integer simulator checks, additive migration test, and exact-money contract docs.

### Verification
- Focused Money/property/policy/identity/static/canonical/regression/simulator set: 59 passed.
- Canonical metadata float attack slice: 29 passed.
- Final full suite: 173 passed, 3 failed. Remaining failures are `test_maker_checker_duplicate_approval_by_same_approver_rejected`, `test_incident_invalid_state_transition_rejected`, and `test_audit_ledger_hash_chain_tamper_detection` in `tests/unit/test_redteam_hardening_pass.py`; these were present in baseline and are outside FG-201/202.
- Deterministic red-team + promoted regression gate: 34 passed.
- CLI `tx create --help`: verified `--amount <str>` decimal-string input.
- Ruff on touched files: still fails due pre-existing lint findings in touched legacy files; 256 total findings reported for selected touched set. No repository-wide lint cleanup performed.
- Final benchmark ran in isolated temporary data: decision N=1000, p50 7.254 ms, p95 17.493 ms, p99 26.186 ms, throughput 115.77 ops/s; money parse/format N=1000 p50 0.0019 ms, p95 0.0021 ms, p99 0.0029 ms; canonical hash N=1000 p50 0.0116 ms, p95 0.0161 ms, p99 0.0323 ms; Ed25519 signature N=1000 p50 0.0284 ms, p95 0.0628 ms, p99 0.0978 ms; ledger 200-entry verify 11.032 ms. These are one local run; hardware/OS metadata was not recorded and no committed baseline comparison was made.

### Remaining M1 Gaps
- No exact representability audit/quarantine/backup/rollback report for pre-existing float rows.
- Transaction table retains the read-only legacy Float column. Existing schemas with `amount NOT NULL` cannot accept new inserts until a table-rebuild migration is provided.
- No property-based lifecycle test across repeated/multiple simulator transfers; representative conservation and rejection-no-mutation checks pass.
- No Windows Actions/CI run or actual pre-change DB signature verification.
- RFC 0001 metadata-binding status was already marked approved in an existing uncommitted document; human approval provenance was not independently verified in this session.

### M1 Authority and Migration Follow-up
- Source audit found effective DecisionEngine authority diverged from `core.authority`: identity source allowlists were not loaded, empty destinations were permissive, and hardcoded treasury source exceptions remained. Added failing tests first; fixed registry loading, explicit empty-list deny, agent-wildcard deny (including literal `*` IDs), audited non-agent wildcard use, and removed the treasury fallback.
- Source audit also found actor/policy minor-unit limits were reinterpreted using transaction currency. Added `authority_currency` to signed actor config (legacy default INR) and fail-closed mismatch handling across decision, policy, risk, helper, and signing paths.
- Added `finguard.storage.money_migration.migrate_legacy_money()` plus `scripts/migrate_legacy_money.py`, dry-run and backup-required apply modes, exact binary-float-to-minor classification, quarantine, v1 tagging, and `MIGRATED_REQUIRES_RESUBMIT` for unsigned legacy states. Tests cover exact, inexact, non-finite, backup, dry-run immutability and idempotence. No operator database was used.
- Added `docs/runbooks/migrate-legacy-money.md`, `docs/MASTER_ROADMAP.md`, and replaced the stale architecture narrative with implementation-backed flow and dependency ordering.
- Focused authority/money/migration suites pass. Previous full-suite run: 183 passed, 3 existing `test_redteam_hardening_pass.py` failures; rerun after the migration/report/doc changes is required.
- The whole-database rewrite attack is only partially mitigated: signing verifies receipt-to-decision audit binding, but the audit hash chain is unsigned and co-located in SQLite. Signed checkpoints/external anchoring remain an M2/M5 blocker.
- Final full suite after these changes: 187 passed, 3 failed (the same three existing `test_redteam_hardening_pass.py` failures). Deterministic AI/product/YAML attack and regression gate: 42 passed.
- Final isolated benchmark: decision N=1000 p50 7.117 ms, p95 9.711 ms, p99 12.857 ms, throughput 133.57 ops/s; money parse/format p95 0.0021 ms; canonical v2 hash p95 0.0165 ms; Ed25519 sign p95 0.0377 ms; 200-entry ledger verify 11.678 ms. Hardware/OS metadata was not recorded.
- `scripts/migrate_legacy_money.py --help` and CLI `tx create --help` verified. Migration apply was NOT run on the operator DB. Make is absent in the Windows shell; repository test/attack commands were run directly with the configured Python 3.13.7 interpreter.

## M2 Idempotency Retry Correction (2026-10-02)

- Starting checkpoint: branch `m1-money`, commit `9bde6ca`; worktree was clean.
- Reproduced a defect in the prior idempotency implementation: replaying the exact same transaction/key returned BLOCK and could rewrite the original transaction state instead of returning its original decision.
- Updated `DecisionEngine` to return the stored decision result for a completed request with the exact same transaction ID and canonical hash. Conflicting key reuse and incomplete/mismatched decision evidence are rejected before the existing fail-closed mutation path.
- Synchronized the first decision result's domain revision with the database CAS version. Regression tests also prove changed content under the same key is rejected without changing the original row or creating a second receipt.
- Focused verification: 2 idempotency regression tests passed.
- Full verification: `py -m pytest -q` -> 196 passed, 0 failed, 36.64s; SQLAlchemy `datetime.utcnow()` deprecation warnings remain.
- Current uncommitted changes: `finguard/decision/engine.py`, `tests/unit/test_security_core_phase2b.py`, `docs/INVARIANTS.md`, `.agent/TASKS.md`, `.agent/LOG.md`. No commit or push was made.
- Limits: completed exact retries are covered only when transaction identity and canonical bytes are identical. Decision UoW atomicity, concurrent idempotency claims, approvals' row-version binding, signing CAS, execution gate consolidation, and crash-injection remain open. M2 is not complete.

## M2.1 Transaction Authority Chain (2026-10-02)

- Starting checkpoint: `m1-money` at `9bde6ca`, with the preceding idempotency fix preserved; fresh pre-implementation baseline was `py -m pytest -q` -> 196 passed, 0 failed.
- Decision receipts now carry the persisted transaction row version; DECISION ledger metadata binds receipt ID/hash, transaction hash/version, and policy version.
- Approval request and approval records carry transaction versions. Approval signatures bind the canonical transaction hash, request/policy/expiry, and the prospective APPROVED row version. Approval keys are checked against actor public keys in the root-signed identity registry; approval ledger evidence is matched to its stored record.
- Signing resolves an active human signer from the signed identity registry, validates decision/approval and the exact authorized row version, and atomically CAS-writes SIGNED state, signature, key ID, and `signed_version`. The existing signature bytes remain canonical transaction v2 bytes; lifecycle version is enforced by the row/artifacts but is not cryptographically included in signature bytes.
- Execution verifies canonical hash/signature, decision receipt + DECISION ledger binding, current identity/authority/policy, required approval and signer evidence, and signed row version. Balance debit/credit, unique execution record, and SIGNED -> EXECUTED CAS share a SQLite transaction. Audit append remains post-commit.
- Added attack coverage for missing decision/approval evidence, forged approved flags, unbound approval/signer keys, stale approval version, mutation after signing, cross-transaction signature substitution, exact idempotent retry/collision, replay, and concurrent signing/execution. Valid approval-backed chain is exercised end to end.
- Test result: final `py -m pytest -q` -> 207 passed, 0 failed, 41.61s. Focused migration, authority-chain, signing, simulator, and red-team slices passed. Ruff `--select F,I` passed on the five core authority-chain modules. SQLAlchemy `datetime.utcnow()` deprecation warnings remain.
- Known M2.2 gaps: decision + nonce + receipt + ledger are not one UoW; approval/signing/execution audit appends are not atomic with their corresponding data writes; no process-level race or crash-injection suite; ledger has no signed checkpoints/external anchor. Signature-version envelope is intentionally unchanged and needs separate security review before any format change.
- M2.1 remains in progress: lifecycle version is checked through stored evidence/CAS but not included in signature bytes; process-level concurrency and crash-boundary proofs remain open. Final commit/push status is reflected by the repository history.

## M2.2 Atomic Transactions and Crash Recovery (2026-10-02)

- Preserved the pre-existing M2.2 simulator work: financial updates, unique execution row, lifecycle CAS, and execution audit evidence share one explicit SQLite transaction. An exact successful retry validates stored execution/audit evidence and returns the same result without repeating the transfer.
- Decision writes share one transaction for transaction + nonce + optional approval request + lifecycle CAS + receipt + DECISION audit. Approval state/audit and signing signature/CAS/audit share their respective write transactions.
- Added inert test checkpoints for decision and execution transaction stages. Tests reload the database after injected failures, assert no partial state/evidence, and retry execution successfully. Approval/signing audit-failure tests prove rollback.
- Existing separate-session threaded signing/execution races remain green; concurrent execution produces one financial effect. Process-level contention/crash tests remain open. Signed ledger checkpoints and external anchoring remain open and are not claimed.
- Focused decision/approval/signing/execution tests: 47 passed. Red-team replay, concurrent execution, and simulator slice: 23 passed. Full `py -m pytest -q`: 219 passed, 0 failed. `git diff --check`: passed.
- Requested Ruff command: 50 findings, identical to committed HEAD; no M2.2 lint regressions remain in the requested files. Additional changed Python files also have no new findings after import/unused-symbol fixes.
- The lint command remains nonzero, so the requested commit/push gate is not met. No commit or push has been made.

## M2.2 Process Concurrency and Version Review Follow-up (2026-10-02)

- A spawned-process race test initially reproduced the deferred SQLite read-to-write failure: one executor completed and the other received a generic concurrent-execution error instead of observing the committed replay.
- Added SQLite `busy_timeout=5000` and issued `BEGIN IMMEDIATE` only at the simulator execution transaction boundary. Re-running the process test passed: both OS processes returned the identical execution result; persisted state was `executed`, balances changed once, and exactly one execution plus one execution audit row existed.
- Added stale signed lifecycle-version regression: after incrementing the persisted row version, execution rejects with no balance mutation. The signature remains over canonical transaction v2 bytes. Version is a CAS token: the API caller cannot set it; SigningGate CAS writes `signed_version` and audit evidence; execution requires row-version equality and matching signing evidence. A full-database rewrite can recompute the unkeyed audit chain, so signing-envelope binding remains open for a separate M2.3/security review rather than changing authenticated bytes here.
- Focused process/recovery suite: 39 passed before the stale-version case was added; final focused decision/approval/signing/execution suite: 49 passed. The spawned-process race passed 3/3 repeated runs.
- Final full suite: `py -m pytest -q` -> 221 passed, 0 failed in 51.37s. Final `git diff --check` and status/history checks follow this log update.
- Lifecycle review outcome: lifecycle `version` is a CAS concurrency token rather than caller-controlled authorization content. SigningGate captures the authorized row version and atomically records `signed_version` with the signature and signing audit; execution requires row version equality plus signing evidence. The stale-version regression proves a changed row version cannot execute. Canonical signature bytes remain unchanged; full-file rewrite can alter/recompute the co-located unkeyed ledger, so signing-envelope binding remains a separate security review item.

## M3 AI/Agent Security Boundary (2026-10-03)

- Starting point: clean, pushed `m1-money` baseline at `24c8732` (M2.3 signed sequenced ledger checkpoints).
- Existing flow observed before implementation: `LocalAIAnalyzer` parses model output into `TransactionExtraction`, but both extraction models use Pydantic's default extra-field behavior; `TreasuryAgent` catches every exception, submits through `FinGuardAgentClient`, then appends a separate agent audit event. `FinGuardAgentClient` has only proposal/inspection methods, but its caller supplies actor ID and proposal source account. The central `DecisionEngine` applies signed-registry identity/authority, policy, risk, replay, approval-floor, receipt, and DECISION-ledger checks. `SigningGate` and `FinancialSimulator` independently revalidate stored evidence; agent transactions require human approval in `PolicyEngine`. The ledger now supports identity-bound signed checkpoints. No product MCP server exists.
- Existing end-to-end proof: `tests/unit/test_llm_to_execution_flow.py` drives a fixed model response through `TreasuryAgent`, human approval, SigningGate, and the simulator. It proves the legacy path's approval floor but does not prove strict intent fields, tool authorization, loop/time budgets, poisoned tool output, or replay binding.
- Ticket FG-402 is scoped to a strict server-bound, one-proposal-call agent boundary and deterministic adversarial tests. M1/M2 authority, transaction canonical bytes, approval/signing/execution semantics, and checkpoint behavior are locked; model output remains advisory and no model path receives signing/approval/secret capabilities.
- FG-402 implementation adds a strict structured intent, server-bound actor/source/timestamp, stable request-derived transaction/nonce/idempotency identifiers, a fixed proposal capability, one-turn limits, cancellation/timeout reconciliation, and exact local transaction/receipt/DECISION-ledger evidence checks. A review found and fixed caller-supplied timestamps and the need to recompute the canonical hash from persisted transaction fields rather than trusting only the stored hash column.
- The local vertical slice stops at `APPROVAL_REQUIRED`; it delegates decisions to `DecisionEngine`, and a passing integration test separately performs human approval, SigningGate signing, simulator execution, and an operator-key-signed ledger checkpoint. No product MCP server, remote adapter, autonomous execution, provider protocol, or model evaluation is implemented.
- Focused validation after these changes: `pytest tests/security/test_agent_security_boundary.py tests/unit/test_llm_to_execution_flow.py tests/unit/test_ai_redteam.py -q` -> 46 passed; the boundary-only file contains 35 passing tests. Full suite: `python -m pytest -q` -> 274 passed, 0 failed. Changed-file Ruff checks pass, Pylance diagnostics are empty for the boundary and treasury facade, and `git diff --check` passes. Final diff review is complete; no M3 commit or push has been made yet.
