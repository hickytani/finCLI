# FIN//GUARD Master Task Backlog

## Status Legend
- `[ ]` Pending
- `[-]` In Progress
- `[x]` Completed

## Backlog

### Day 1 - Project Hygiene & Baseline Hardening
- [x] Baseline setup, ruff cleanup, test matrix, branch coverage setup
- [x] Initial architecture documentation (`docs/ARCHITECTURE.md`)
- [x] Initial invariants specification (`docs/INVARIANTS.md`)
- [x] Appendix A vulnerability catalog regression tests (`tests/unit/test_redteam_hardening_pass.py`)
- [x] Performance baseline benchmark script (`scripts/bench.py`)

### Day 2 - Money Correctness & Identity Registry (F1, F2)
- [ ] F1: Introduce `Money(minor_units: int, currency: Currency)` decimal string representation ("500.00").
- [ ] F1: Per-currency exponent table, reject excess precision.
- [ ] F1: Canonical serialization v2 with integers/strings & domain-separated prefix (`finguard.tx.v2\0`).
- [ ] F1: Read-only legacy v1 verification path for existing receipts/signatures.
- [ ] F1: Property-based tests (Hypothesis) for money roundtrip, float rejection test.
- [ ] F2: Remove hardcoded `"rahul"` and `"treasury"` identifiers from `ai/schemas.py` and `decision/engine.py`.
- [ ] F2: AccountRegistry resolving alias -> account id (unresolved -> BLOCK with UNRESOLVED_ACCOUNT).
- [ ] F2: Source-account authority from `allowed_source_accounts` in identity registry.
- [ ] F2: Reject confusables, zero-width, mixed-script identifiers; require NFC.

### Day 3 - Concurrency, State Machine & Ledger Integrity (F3, F4, F5)
- [ ] F3: Atomic decision unit of work (nonce claim + receipt + state change + ledger append commit together).
- [ ] F3: Injected session / Unit-of-work in decision & signing paths; remove global `get_session()` calls.
- [ ] F4: Compare-and-swap (CAS) signing gate (`UPDATE ... WHERE state = expected`).
- [ ] F4: Concurrency test suite (50 parallel sign attempts -> exactly 1 succeeds).
- [ ] F5: Monotonic sequence `seq` with `UNIQUE(seq)` and `UNIQUE(prev_hash)` in ledger.
- [ ] F5: Periodic and on-demand signed checkpoints `{seq, head_hash, ts, key_id, signature}`.
- [ ] F5: Ledger audit verify with chain and checkpoint validation (200 parallel appends gap-free).

### Day 4 - LLM Layer & Evaluation Harness (F6)
- [ ] F6: `LLMProvider` protocol (Ollama & OpenAI-compatible HTTP implementations).
- [ ] F6: Eval harness with benign set + attack catalog (N >= 30 variants per category).
- [ ] F6: Reproducible multi-model report (`docs/RESULTS.md`) with Wilson 95% CIs.

### Day 5 - MCP Server Implementation (F7)
- [ ] F7: FastMCP package `finguard.mcp` exposing ONLY `propose_transaction`, `get_decision`, `list_transactions`, `get_audit_proof`.
- [ ] F7: Server-side actor binding, tool description poisoning defense, MCP security test suite.

### Day 6 - Signer Abstraction & Guardrail Comparison (F8)
- [ ] F8: `Signer` interface, `KmsSignerStub` implementation.
- [ ] F8: Guardrail benchmark comparison (NeMo, LLM Guard, Llama Guard vs FIN//GUARD).

### Day 7 - Release & Recruiter Packaging (F9)
- [ ] F9: PyPI release 0.2.0 packaging, CHANGELOG, SECURITY.md, docs/CASE_STUDY.md, demo script.
- [ ] F9: Final honest README audit with reproducible commands & measured numbers.
