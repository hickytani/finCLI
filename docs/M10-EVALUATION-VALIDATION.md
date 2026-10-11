# M10 — Independent Evaluation Validation

## Scope and verdict

M10 hardens the M9 synthetic comparative evaluation in `finguard/evaluation/` and its security tests. The latest run addresses the extraction leak, the blocked legitimate controls, and reliability fixtures that previously did not exercise the provider failure modes they claimed to test.

This is a deterministic local evaluation, not a comparison against a live model or an external agent framework. The synthetic baseline and all results apply only to the 36 fixtures in this corpus.

## Findings and changes

- **G4 extraction disclosure:** a synthetic bearer-shaped value survived in the extracted `reason`. Redaction now occurs at the LangChain extraction boundary, before the result leaves the adapter; a regression test checks the returned extraction rather than merely changing the evaluator's detector.
- **Positive controls:** two controls were blocked because their previous USD/EUR proposals did not match the configured test actor's INR authority. The controls now use INR and the already-allowlisted `vendor-a` / `vendor-b` destinations. All four reach `REQUIRE_APPROVAL`; authority, policy, approval, and execution rules were not weakened.
- **Provider reliability:** fixtures deterministically trigger an actual timeout, retry exhaustion (three observed invocations: initial attempt plus two retries), and a provider exception containing a synthetic sentinel. These are reported as reliability outcomes rather than executable attacks or successful blocks.
- **Evaluator correctness:** extraction is reused from the pipeline result instead of invoking the provider a second time. Unexpected evaluator exceptions propagate. Secret disclosure is part of the attack oracle, and pre-existing protected database rows are compared across all columns so edits and removals are detected.
- **Timeout behavior:** the adapter returns at the deadline without waiting for the worker thread. Cancellation is cooperative; Python cannot forcibly stop provider code already running in that thread.

## Latest recorded results

The generated scorecard is [`M9-RESULTS.json`](./M9-RESULTS.json), timestamped `2026-10-11T14:27:13.627916+00:00`.

| Measure | Observed result |
|---|---:|
| Total fixtures | 36 |
| Adversarial fixtures | 32 |
| Executable-attack fixtures evaluated | 29 |
| Reliability-only cases exercised | 3 |
| Inconclusive / unexercised cases | 0 |
| Synthetic baseline reference successes | 28 / 29 |
| Guarded attack successes | 0 / 29 |
| Blocking among baseline-successful attacks | 28 / 28 (100%) |
| Legitimate controls accepted | 4 / 4 (`REQUIRE_APPROVAL`) |
| False-denied legitimate controls | 0 |
| State-integrity violations | 0 |

The reliability-only outcomes are F3 `timeout` after one attempt, F4 `retry_exhausted` after three attempts, and G3 `exception` after one attempt. G3's synthetic sentinel was not present in the observed result or captured logs. G4's bearer-shaped sentinel was redacted from the extraction reason.

These corpus-specific measurements are not a general attack-success probability or a production-security claim. In particular, the baseline is a small synthetic reference rule, and the local reliability fixtures do not establish live-provider behavior.

## Validation recorded

The latest local validation used Python 3.13.7 on Windows:

- Focused M8/M9 security tests: **46 passed**, 24 SQLAlchemy deprecation warnings, in 12.18 seconds.
- Full repository test suite: **819 passed**, 761 SQLAlchemy deprecation warnings, in 138.64 seconds.
- CI coverage selection (`pytest -v --cov=finguard --cov-branch --cov-report=term-missing --cov-fail-under=71 -m "not slow" tests/unit/ tests/regression/ tests/security/ tests/property/`): **810 passed**, **71.05% branch coverage**, in 155.15 seconds.
- Ruff: passed.
- `scripts/check_invariants.py`: passed; all 94 cited tests were found.
- `git diff --check`: passed after the generated-scorecard timestamp refresh and validation-document update.

The earlier GitHub Actions run for commit `ac4ff6b2ee0fb444d4a499d34e860a7148c24df5` has contradictory evidence: the Python 3.13 job log prints `FAIL Required test coverage of 71% not reached. Total coverage: 70.77%`, while the Actions API reports the coverage step and job as successful. That run predates the two new extraction-security regression tests. A new CI run on the updated commit is required to resolve the discrepancy; local Windows coverage alone is not evidence that Linux CI meets the gate.

The SQLAlchemy warnings concern existing uses of `datetime.utcnow()` and were not changed as part of this work.

## Worktree handoff

The initial M10 changes are committed and pushed on `m10-eval-oracle-hardening` as `ac4ff6b2ee0fb444d4a499d34e860a7148c24df5`; PR [#16](https://github.com/hickytani/finCLI/pull/16) targets `main` and remains open and unmerged. The two new regression tests and regenerated scorecard have not yet been committed or pushed. The verified remote is `hickytani/finCLI`; the previously fetched `origin/main` was `6acee3b3f3aca09c79ccf3b20fba4f5b582288aa`. No merge or change to the original checkout or its stash was made.
