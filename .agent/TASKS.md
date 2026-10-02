# FIN//GUARD Master Task Backlog (Prompt v2: M0 - M6)

## Status Legend
- `[ ]` Pending
- `[-]` In Progress
- `[x]` Completed

## Milestone Roadmap

### M0 - Mission Control (FG-001)
- [x] AGENTS.md v2 prompt integrated as single source of truth.
- [x] Reproducible defect proof suite created: `tests/regression/test_baseline_findings.py` (FG-201..FG-206).
- [x] DevTools MCP server implemented: `tools/devtools_mcp.py` (`run_tests`, `run_attacks`, `run_bench`, `invariant_status`, `list_open_tickets`).
- [x] Makefile with targets (`watch`, `t0`, `t1`, `t2`, `t3`, `attack`, `attack-loop`, `bench`, `migrate-dry`, `docs`).
- [x] Invariants matrix updated to I1-I14 in `docs/INVARIANTS.md`.
- [x] Baseline performance benchmark script (`scripts/bench.py`) committed.

### M1 - Money and Authority (FG-201, FG-202, FG-203, FG-204, FG-205, FG-206)
- [ ] FG-201/202: `Money(minor: int, currency: Currency)` class + per-currency exponent table.
- [ ] FG-201/202: Reject excess precision, NaN, Infinity, negative, zero, bool-as-number at boundary.
- [ ] FG-201/202: Canonical v2 serialization (`finguard.tx.v2\x00` domain prefix, `amount_minor` integer).
- [ ] FG-201/202: Legacy v1 read-only verification path & golden test vectors.
- [ ] FG-201/202: AST test `test_no_float_money` enforcing 0 float in money paths.
- [ ] FG-203/204: `AccountRegistry` (`accounts` table, alias resolution, NFC/NFKC validation, confusable rejection).
- [ ] FG-203/204: Deny-by-default `Authority` (`allowed_destinations`, `allowed_source_accounts`).
- [ ] FG-203/204: Remove `"rahul"` and `"treasury"` hardcoded literals.
- [ ] FG-205: Simulator balances in minor units (integer math, conservation invariant property test).
- [ ] FG-206: RFC 0001 (`docs/rfcs/0001-bind-metadata.md`) & `metadata_digest` binding in canonical v2.

### M2 - Integrity and Atomicity (FG-301, FG-302, FG-303, FG-304)
- [ ] FG-301: Atomic Unit of Work for decision pipeline (single session, `BEGIN IMMEDIATE`, SQLite WAL).
- [ ] FG-302: CAS signing gate (`UPDATE ... WHERE state = expected`).
- [ ] FG-303: Monotonic `seq` ledger, SQLite triggers, signed checkpoints `{seq, head_hash, ts, key_id, signature}`.
- [ ] FG-304: Unified aware-UTC `Clock` service; remove naive `_utcnow()` shim.

### M3 - LLM Provider Layer & Evaluation Harness (FG-401)
- [ ] FG-401: `LLMProvider` protocol (Ollama & OpenAI-compatible HTTP providers).
- [ ] FG-401: Evaluation harness (benign + attack catalog with >= 30 variants per category).
- [ ] FG-401: Multi-model evaluation report (`docs/RESULTS.md`) with Wilson 95% CIs.

### M4 - FIN//GUARD MCP Server (FG-501)
- [ ] FG-501: FastMCP package `finguard.mcp` exposing ONLY `propose_transaction`, `get_decision`, `list_transactions`, `get_audit_proof`.
- [ ] FG-501: Structural import isolation & server-side identity binding.

### M5 - Comparison and Signer Abstraction (FG-601, FG-602)
- [ ] FG-601: `Signer` interface and `KmsSignerStub`.
- [ ] FG-602: Comparative benchmark vs NeMo Guardrails, LLM Guard, Llama Guard.

### M6 - Release Engineering & Recruiter Packaging (FG-701)
- [ ] FG-701: PyPI v0.2.0 packaging, CHANGELOG, SECURITY.md, SBOM (CycloneDX), Scorecard.
- [ ] FG-701: `docs/CASE_STUDY.md`, 3-minute demo script, README audit with measured numbers.
