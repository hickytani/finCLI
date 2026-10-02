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
- [-] Makefile target names exist; `docs` remains a placeholder and `attack-loop` is not the documented seeded randomized fail-fast loop.
- [x] Invariants matrix updated to I1-I14 in `docs/INVARIANTS.md`.
- [x] Baseline performance benchmark script (`scripts/bench.py`) committed.

### M1 - Money and Authority (FG-201, FG-202, FG-203, FG-204, FG-205, FG-206)
- [x] FG-201/202: Immutable `Money(minor_units: int, currency: Currency)` + explicit exponent table (INR/USD/EUR/JPY/KWD).
- [x] FG-201/202: Reject excess precision, NaN, Infinity, negative, zero, bool-as-number, floats, and malformed amount syntax.
- [x] FG-201/202: Canonical v2 domain prefix and integer `amount_minor`; new transactions cannot select v1; v2 timestamps normalize to UTC.
- [-] FG-201/202: Separate legacy v1 serializer and golden vector exist; CLI read-only verification exists but has not been exercised against a complete pre-change DB artifact.
- [x] FG-201/202: AST regression test for float conversions/monetary annotations in authoritative paths.
- [-] FG-201/202: Dry-run/apply exact legacy-float audit, quarantine table, backup-before-write, unsigned resubmit failure, and populated fixtures exist; operator-database run, rollback/restore exercise, and pre-v2 signed artifact verification remain.
- [x] FG-203: Effective decision/helper paths deny empty source/destination/action lists; signed source lists load; agent wildcards deny; non-agent wildcard use is recorded.
- [x] FG-203: Actor authority limits, policy thresholds, risk comparisons, and signing revalidation reject currency mismatches.
- [ ] FG-203: Existing actor allowlists need explicit migration/report and reviewed operator wildcard override workflow.
- [ ] FG-204: `AccountRegistry` table, alias resolution, mixed-script/confusable rejection, and currency-bound accounts.
- [ ] FG-204: Remove remaining hardcoded account literals from defaults/CLI/simulator.
- [x] FG-205: Simulator balances and transfers use integer minor units with representative conservation/no-mutation tests.
- [ ] FG-205: Multi-transfer conservation property and cross-currency account enforcement.
- [x] FG-206: Metadata digest is included in v2; RFC 0001 is present but human approval provenance remains unverified.

### M1 Exit Blockers
- [ ] Independent verifier sign-off and human approval for canonical byte/golden-vector change (G6).
- [ ] Fix three pre-existing `test_redteam_hardening_pass.py` failures before claiming the repo suite is green.
- [ ] Finish legacy database audit/quarantine/rollback and actual pre-change v1 artifact verification.
- [ ] Signed ledger checkpoints/external anchoring remain necessary against full SQLite-file rewrite.

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

## Master Dependency Ordering

M0 mission control -> M1 exact money and effective authority -> M2 state
machine, atomic UoW, signing CAS, sequenced/checkpointed ledger, and clock. M3
provider/evaluation and M5 trusted signer/evidence tracks may proceed only after
their deterministic inputs and M2 interfaces are stable. M4 product MCP depends
on the proven core APIs and must not expose current non-atomic paths. M6 full
adversarial evaluation depends on M3/M4/M5; M7 release engineering follows
reproducible evaluation; M8 is final research-grade system evaluation. See
`docs/MASTER_ROADMAP.md` for the source-backed status matrix.
