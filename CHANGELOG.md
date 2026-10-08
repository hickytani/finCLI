# Changelog

All notable changes to FIN//GUARD are documented here.

The format follows [Keep a Changelog](https://keepachangelog.com/en/1.0.0/).
This project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [Unreleased]

### Planned
- PyPI Trusted Publishing setup (human gate required)
- OpenSSF Scorecard integration
- External ledger anchoring (git tag / transparency log)
- KMS signer abstraction (FG-601/602)
- Forced process-death recovery tests
- Process-level decision/signing contention tests

---

## [0.2.0] - 2026-10-08

### Security
- **FG-401** – Full LLM provider security audit; 52-case adversarial evaluation harness; fail-closed on any extraction error.
- **FG-201** – Fixed signature binding: `Transaction(amount=100.001)` and `amount=100.004` now produce distinct hashes via integer `amount_minor`; `0.001` is no longer silently rounded to `0.00`.
- **FG-202** – Reject NaN, Infinity, booleans, negative, and zero amounts at the `Money` boundary; `1e22` is above `MAX_AMOUNT_MINOR` and is rejected.
- **FG-203** – `Authority` deny-by-default: empty `allowed_destinations` now means NONE (was: allow all). `"*"` is explicit, emits `WILDCARD_AUTHORITY` signal, and is rejected for AGENT actors unless an operator override is set and logged.
- **FG-204** – Removed hardcoded `"rahul"` and `"treasury"` literals; account resolution goes through the `AccountRegistry`.
- **FG-205** – Simulator balances stored as `balance_minor BIGINT`; float arithmetic eliminated from execution paths.
- **FG-206** – `metadata_digest` bound into canonical v2; approvers sign exactly the stored metadata (RFC 0001).

### Added
- **M3.1** – `StructuredIntentBoundary`: strict schema validation, identity binding, NFC normalization, zero-width/control character rejection.
- **M3.2** – `AgentGuardrails`: deterministic budget enforcement (step, tool, value limits), injection-pattern blocking, authority-field stripping with `authority_fields_detected` audit.
- **M4** – Bounded agent orchestration loop: immutable `CapabilityProfile`, guarded `ToolRegistry`, deadline/step/budget enforcement; orchestrator cannot approve, sign, or mutate policy.
- **M5** – Secure MCP boundary (`finguard/mcp/`): `propose_transaction`, `get_decision`, `list_transactions`, `get_audit_proof` only; signing/approval/key surfaces structurally absent.
- **M6** – Agentic Security MVP: `finguard/agent/loop.py`, `capabilities.py`, `tools.py`, CLI command `finguard agent run`.
- `docs/CURRENT-ARCHITECTURE.md` – Live 9-layer security architecture diagram.
- `docs/GUARDRAILS.md` – Deterministic guardrail specification and boundary contracts.
- `docs/LIMITATIONS.md` – Honest research-grade limitations (not production-ready).
- `docs/INVARIANTS.md` – I1–I14 invariant table with enforcement points and test pointers.
- `SECURITY.md` – Coordinated disclosure policy.
- `CONTRIBUTING.md` – Contribution guidelines.
- `CODEOWNERS` – Code ownership assignments.
- GitHub issue and PR templates.
- `SBOM.json` – CycloneDX software bill of materials.
- `docs/CASE_STUDY.md` – Problem statement, threat model, design decisions (with ADR links), results, limitations.

### Changed
- `Money` type: `minor: int` + `currency`; parse from `str`/`int`/`Decimal` only (never `float`).
- `canonical_serialize` v2: domain-separated preimage `b"finguard.tx.v2\x00"`, `amount_minor` integer, NFC-validated strings.
- `AuditLedger`: monotonic `seq`, `UNIQUE(seq)`, `UNIQUE(prev_hash)`, append-only SQLite triggers.
- `SigningGate`: re-validates from stored facts, signs v2 only; CAS `UPDATE ... WHERE state='approved'`.
- `DecisionEngine`: broken into individually testable steps; injected `Clock` (aware-UTC throughout).
- Database: `amount_minor BIGINT`, `balance_minor BIGINT`; legacy float rows quarantined during migration.
- Policy YAML: amounts as int or quoted string; YAML floats validated for exactness at currency precision.
- CI: coverage gate 71%, Python 3.12 + 3.13 matrix, `--cov-branch`.

### Removed
- `float` in all money paths (enforced by `test_no_float_money` AST gate).
- Hardcoded actor literals in decision engine.
- Naive `datetime.utcnow()` replaced by injected `Clock` with aware-UTC.

### Fixed
- Ledger hash chain gap via `UNIQUE(seq)` constraint.
- Silent rounding in `canonical_amount()` (now `amount_minor` integer, no rounding).
- `Authority` allow-all default (now deny-by-default; wildcard is explicit).

---

## [0.1.0] - 2026-09-28

### Added
- Initial prototype: Typer CLI, Pydantic v2 models, SQLAlchemy 2 / SQLite, Ed25519 signing (cryptography + PyNaCl), argon2-cffi keystore, networkx-based policy graph.
- `DecisionEngine` with identity, authority, policy, risk, nonce-claim, and receipt.
- `ApprovalService`: hash-bound, expiring, approver ≠ requester.
- `SigningGate`: re-validate then sign; CAS signing.
- `FinancialSimulator`: synthetic INR/USD/EUR balances, integer minor units.
- `AuditLedger`: hash-chained entries, Ed25519 checkpoint signatures.
- Baseline 64 tests; `tests/regression/test_baseline_findings.py` with 5 strict-xfail proof tests.
- GitHub Actions CI: ruff lint + pytest on Python 3.12/3.13.
- Dependabot.

---

[Unreleased]: https://github.com/hickytani/finCLI/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/hickytani/finCLI/compare/v0.1.0...v0.2.0
[0.1.0]: https://github.com/hickytani/finCLI/releases/tag/v0.1.0
