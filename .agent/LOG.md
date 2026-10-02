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
