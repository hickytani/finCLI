# FIN//GUARD Project Assessment

**Assessment date:** 2026-10-05  
**Repository:** `hickytani/finCLI` (`finguard`)  
**Local branch:** `m4-bounded-orchestration`  
**Local HEAD:** `abce1a35c7c73762506a282633a8177a98f9b3a0`  
**Remote baseline:** `origin/main` at `7b123d3c57d68d18037165c0c7be297e898932b6`  
**Purpose:** Evidence-based inventory, progress review, quality assessment, open-work list, and practical market-value discussion.

## Executive summary

FIN//GUARD is a local-first Python security research prototype for putting a
deterministic authorization boundary between an untrusted AI/agent request and
a simulated financial action. Its strongest implemented ideas are exact
integer-minor-unit money, canonical transaction v2, root-signed actor
configuration, hash-bound approvals, signing revalidation, SQLite concurrency
controls, signed ledger checkpoints, an integer-balance simulator, a structured
agent intent boundary, and a bounded orchestration prototype.

The project has substantial implementation and test coverage for an individual
open-source project. On the inspected checkout, the full test suite passes:
**313 passed** on Python 3.13.7. Measured branch coverage is **71%**. Ruff
currently fails with one import-format/whitespace finding, and pytest emits
hundreds of SQLAlchemy-related deprecation warnings. Those are the measured
local results, not historical figures.

The most important qualification is that a passing suite does not make every
documented M4 guarantee true. Runtime checks against the current orchestrator
confirmed that the public `start()` capability argument can replace the
configured capability set, an empty capability set becomes
`transaction.propose`, and an `APPROVAL_REQUIRED` run can be advanced to
`COMPLETED` by calling `complete()`. The orchestrator module is currently not
connected to a user-facing service or MCP server, so this is a gap in the new
M4 boundary and its claims—not evidence of a demonstrated real-money attack.

The repository has not had a packaged release or tagged version in the
inspected Git history. GitHub currently reports zero stars, zero forks, no
Actions workflows/runs, and one historical merged pull request. There is no
revenue, customer, adoption, or paid-market evidence here from which to
calculate a defensible company or product valuation. At present its credible
value is as an early-stage technical portfolio/research project and a foundation
for further product validation, not as a validated commercial security
product.

## Scope and method

This assessment inspected the repository root and all tracked path groups,
the current branch and local diff, project configuration, README, roadmap,
invariants, M4 documentation, source modules, tests, historical audit notes,
and GitHub repository/branch/PR/Actions metadata. It ran the full test suite,
branch-coverage suite, Ruff, and focused runtime checks using the checked-in
Python 3.13.7 virtual environment.

The working directory also contains ignored runtime data, cache directories,
and a `test-tmp-phase2c-small` directory that denied listing. These were not
read or modified. They are not counted as tracked project content.

This is an engineering/product assessment, not a penetration test, legal
opinion, financial appraisal, or independent security certification.

## Repository and GitHub snapshot

| Measure | Observed |
|---|---|
| Tracked files | 156 |
| Tracked `finguard/` paths | 88 |
| Tracked `tests/` paths | 27 |
| Tracked `docs/` paths | 27 |
| Current branch | `m4-bounded-orchestration` |
| Current HEAD | `abce1a3` (`feat(m4): add bounded agent orchestration`) |
| Current feature commits after `origin/main` | 1 |
| Remote GitHub branch for M4 | None observed |
| Local unstaged user edit | `finguard/decision/engine.py` (one blank whitespace-only line in imports) |
| Local Git identity | `hickytani`, `prasun051205@gmail.com` |
| GitHub repository identity | `hickytani/finCLI` |
| GitHub public metadata | Python; description “automated inspecting CLI”; 0 stars, 0 forks, 0 open issues |
| Releases/tags | No Git tags or release observed |
| GitHub Actions | No workflows or workflow runs returned |
| Pull requests | One historical merged PR, `#1` (“M1 money”) |
| Connected GitHub permissions | Read access; push permission not available to this session |

The M4 commit is only in the local checkout and is not on a published remote
branch. The remote's default branch is `main`; published branches observed were
`main`, `day2-money`, `m1-money`, and `m3.1-structured-intent`. Local Git
identity already uses the repository owner's username. No GitHub changes were
made because the connected account does not have push permission. No commit was
created, so this report does not silently include unrelated working-tree
changes.

## What the project does today

The source implements a local transaction decision and simulation stack:

1. CLI, SDK, structured intent, or local model extraction supplies a proposal.
2. `Money` parses supported amounts into integer minor units and rejects float
   inputs, excess precision, malformed syntax, and non-positive amounts.
3. New transactions use canonical v2 fields and a domain-separated hash;
   metadata is digest-bound. Legacy v1 serialization is retained for
   compatibility paths.
4. Actor identity and authority are loaded from a signed local registry.
   Decision and policy logic evaluate actor grants and limits.
5. Decision, approval, signing, and simulated execution use persisted
   transaction/receipt/evidence checks. Signing uses CAS-style state updates;
   the simulator uses SQLite transactions and integer balances.
6. The audit ledger is sequenced and supports identity-key-signed checkpoints.
7. AI extraction is local/advisory; structured agent intent validates a
   proposal before it enters the existing decision pipeline.
8. The current feature branch adds an in-memory bounded planner/orchestrator.
   It is not an MCP product server and does not persist resumable orchestration
   sessions.

This is synthetic/local execution only. The project does not connect to a bank,
payment rail, custody service, or real funds.

## Implemented strengths

- **Exactness:** New authoritative amounts use integer minor units and explicit
  currency exponents. There is a dedicated AST regression test against floats
  in authoritative money paths.
- **Canonical transaction work:** v2 has a domain prefix and integer amount
  field; metadata is covered by a digest; v1 verification support and a v1
  vector are retained.
- **Independent authority boundary:** The intended system places identity,
  policy, approval, signing, and execution outside the model. SDK proposal APIs
  are separated from operator-only signing/approval actions.
- **Cryptographic controls:** The code includes Ed25519 signing, an encrypted
  local keystore, hash-bound approvals, signer/approver registry checks, and
  final transaction revalidation.
- **Persistence controls:** State CAS, nonce/idempotency controls, atomic
  evidence writes, process/thread race tests, and rollback injection tests
  exist in the current source/test set.
- **Auditability:** SQLite ledger sequencing, signed checkpoints, offline
  checkpoint verification, and tamper-oriented tests exist. External anchoring
  is still required to defend against replacement of an entire local database
  and its latest checkpoint.
- **AI honesty:** The repository documents the narrow local model experiment
  and distinguishes invalid output, approval-reaching requests, and actual
  executions rather than calling every non-execution a security block.
- **Documentation:** There are architecture, threat-model, migration, invariant,
  quantitative-evaluation, security-review, and product-gap documents. Some
  material is stale or contradicts current code, as detailed below.
- **Test breadth:** Tests cover unit, regression, security, and property-based
  money checks. The measured current full-suite run is green.

## Local verification results

| Check | Result | Interpretation |
|---|---|---|
| Full pytest suite, Python 3.13.7 | **313 passed**, 0 failed, 97.94 s | Current checkout passed; 743 warnings, mainly SQLAlchemy `datetime.utcnow()` deprecation warnings |
| Full suite with branch coverage | **313 passed**, 0 failed, 71% total branch coverage, 124.84 s | Below the intended 85% overall target; critical-module 95% target not separately demonstrated |
| Ruff `check .` | **Failed: 1 finding** | Import-format/whitespace error in `finguard/decision/engine.py`, on the already-dirty blank line |
| Git diff whitespace check | Existing difference is whitespace-only | Current local user edit is not changed by this report |
| Python interpreter | Python 3.13.7 | Python 3.12 was not tested in this assessment |
| GitHub CI | No workflows/runs returned | No remote CI evidence for the current branch |
| AI attack experiment | README/docs report 100 attempts, 0 unauthorized execution | Historical documented result; not rerun as part of this assessment |
| Deterministic red-team result | README reports 17/17 checks | Historical documented result; the present full unit suite passed, but the separate CLI experiment was not rerun |

## Confirmed current M4 issues

The following were observed directly in `finguard/agent/orchestrator.py` and
confirmed with the configured interpreter. These findings should be treated as
M4 correctness/security-boundary defects. The public orchestrator is not yet
wired into an external financial service, which limits demonstrated impact.

| Priority | Finding | Evidence and likely impact |
|---|---|---|
| High | Caller can replace the configured capability set when starting a run. | `start(..., capabilities=...)` copies the supplied list directly into the run instead of intersecting it with a trusted grant. Runtime check: an orchestrator configured for `transaction.propose` accepted `transaction.admin`. This contradicts the claim that a run cannot self-grant capabilities. |
| High | Empty capability lists silently become the default proposal capability. | `capabilities or default` treats `[]` as missing. Runtime check: `start(..., capabilities=[])` produced `('transaction.propose',)`. This violates deny-by-default expectations. |
| High | Approval-required state can be converted into successful completion. | `APPROVAL_REQUIRED` allows transition to `EXECUTION_BOUNDARY`; `complete()` assigns that state and transitions to `COMPLETED` without proof of an external approval. Runtime check: an amount above the run limit became `APPROVAL_REQUIRED`, then `COMPLETED` after `complete()`. |
| Medium | Budget exhaustion raises but leaves the run in a resumable nonterminal state. | Runtime check: a tool-call-limit error left state at `observation`. A caller that catches the exception may continue using the same run or repeatedly call operations; this does not match the M4 document's promise of a terminal fail-closed state. |
| Medium | Tool callables are supplied at execution time, separate from the name allowlist. | `execute_tool()` accepts an arbitrary `OrchestrationTool.function` when the caller provides it. The name allowlist alone does not prove the invoked callable is the trusted implementation registered by the host. No production service currently wires this API, but integration should require host-owned tool registration. |
| Medium | M4 has very little direct test coverage. | `tests/unit/test_bounded_orchestration.py` has four tests. It does not test empty grants, capability override, calling `complete()` from approval-required, or terminal behavior after budget failure. |

Do not represent these as a successful financial-action exploit: the runtime
checks demonstrate violations inside the orchestration API, not that an
unauthorized transaction reaches the signing gate or simulator. Correct them
and add regression tests before treating M4 as an enforced security boundary.

## Remaining product and engineering gaps

### Roadmap / security

- No product `finguard.mcp` server is present; only the engineering helper
  `tools/devtools_mcp.py` exists. Product MCP isolation and its attack tests are
  therefore not implemented or proven.
- The AI provider abstraction and reproducible multi-model evaluation with
  Wilson confidence intervals are still open.
- The 100-attempt local AI evaluation is a narrow fixed corpus. It is not a
  measurement of general model safety or performance, and external scanners /
  comparator guardrails are not evidenced.
- Account alias registry, mixed-script/confusable validation, legacy authority
  migration/reporting, and removal of hardcoded account defaults remain open.
- Migration fixtures exist, but the runbook and task list say a populated
  operator-shaped legacy database, backup restore, rollback drill, and old v1
  signed-artifact verification are not fully verified. Do not run migration on
  user data without explicit authorization.
- Invariant documentation is inconsistent: the roadmap/task backlog uses one
  milestone/invariant set, while the current invariants file has expanded to
  I34 and has statuses that still mark MCP unimplemented. It must be reconciled
  against code and test evidence.
- A single injected Clock, forced process-death commit recovery, generated
  multi-transfer conservation property test, and external ledger anchoring are
  not yet evidenced.
- No independent verifier or human approval record for canonical/signature
  format changes was observed. Those changes require the project's specified
  approval gate.

### Delivery / operations

- There is no tracked GitHub Actions workflow, release tag, published version,
  SBOM/provenance, or reproducible release pipeline in the observed tree.
- Ruff is a required Make target but does not currently pass. `make docs` is a
  placeholder that prints success rather than building/checking documentation.
- The Makefile uses `.venv/Scripts/...`, which is Windows-specific and is not a
  portable cross-platform Makefile as written.
- The checked-out working tree has an ignored `.finguard/` data directory.
  Sensitive local state must remain excluded from commits; do not share or
  publish runtime database or keystore material.
- README experiments and architecture claims should be dated, traceable to
  commands/artifacts, and separated from current branch verification. The
  README's older security finding says agent source is hardcoded to `treasury`,
  while roadmap requirements say to remove such literals. The current SDK and
  registry still contain treasury defaults, so this claim needs accurate
  qualification rather than assuming the identifier has been eliminated.

## Documentation conflicts and freshness

- `docs/MASTER_ROADMAP.md` is headed as M4/current but retains an older snapshot
  paragraph naming a different branch and baseline commit.
- `docs/architecture.md`, `docs/reality-matrix.md`, `docs/INVARIANTS.md`,
  `docs/MASTER_ROADMAP.md`, `.agent/TASKS.md`, and the older phase reports
  contain different completion states. Some sections are explicitly historical;
  others read as current. This makes it difficult for reviewers to identify the
  live source of truth.
- The root `README.md` documents the M1/M2 core and historic experiments, but
  does not explain the current M4 orchestration branch or its unproven limits.
- The project/package description “automated inspecting CLI” does not explain
  the actual security gateway purpose.
- This assessment adds a dated snapshot; it does not replace or silently rewrite
  the historical audit records.

## Practical market-value assessment

### What can be valued from available evidence

The repository currently has **no defensible numeric company valuation**. The
evidence reviewed contains no revenue, paid users, contracts, deployment
footprint, customer retention, conversion funnel, validated willingness to pay,
or investor financing. GitHub showing zero stars/forks and no published release
is a weak adoption signal, not a valuation method.

The MIT-licensed codebase can have non-zero **portfolio, educational, and
research-option value** to its maintainer: it demonstrates a coherent security
problem, hands-on financial-control engineering, adversarial testing, and
honest limitations. That is different from a market-tested product asset.
Public open-source availability also means code alone is not a durable
commercial moat.

### Buyer/user problem and possible wedge

The problem—constraining tool-using AI agents before sensitive actions—is
credible and timely. FinGuard's plausible wedge is a small, inspectable,
financial-action authorization boundary with exact money and cryptographic
evidence. The project itself acknowledges that IAM, approval workflows,
payment authorization, and agent guardrails already exist; novelty should not
be claimed without comparative evidence.

Potential users might include agent-platform engineers, fintech security teams,
or researchers evaluating agent-to-payment controls. No customer interviews or
design-partner evidence were found in the repository, so these are hypotheses,
not existing demand.

### Why commercial value is not validated yet

- It is local-only and simulated; there is no bank/payment integration or
  deployment story.
- The product MCP interface, production identity integration, remote policy
  administration, managed signer/HSM/KMS support, and operations controls are
  absent or roadmap work.
- A first-party orchestration milestone currently has confirmed grant/approval
  state gaps.
- No deployment security review, independent audit, support/SLO commitment,
  customer proof, or competitive benchmark exists in the inspected evidence.
- There is no release/CI pipeline substantiating software supply-chain and
  maintenance claims.

### Commercial conclusion

**Current status: technically ambitious prototype / portfolio project; not yet
a validated commercial security product.** A numeric dollar figure would be
made up. The nearest meaningful next valuation work is not a spreadsheet
multiple: first close the M4 findings, establish a clean reproducible release
and CI baseline, interview target buyers, validate integration requirements,
and run a controlled design-partner pilot with independently reviewed threat
boundaries. Reassess value only after evidence such as active deployments,
conversion/retention, willingness to pay, support cost, and independently
reproducible security outcomes exists.

## Recommended priority order

1. Add regression tests and fix the four M4 state/grant/budget defects before
   calling the orchestrator fail-closed or bounded.
2. Make trusted capability and tool grants originate in host configuration or
   the signed identity registry; reject empty and untrusted overrides.
3. Reconcile current architecture, roadmap, invariant, and task-status
   documents; date/archive stale snapshots instead of leaving them ambiguous.
4. Restore a clean Ruff gate, eliminate deprecation warnings, and add automated
   CI on Python 3.12 and 3.13.
5. Keep MCP and LLM-evaluation work behind the already stated dependency gates;
   document absent capability as absent.
6. Complete migration drills only against disposable copies, with backup and
   restore evidence.
7. Use buyer interviews and a narrow non-production pilot to test demand before
   estimating commercial value.
8. Publish the M4 branch through the correct `hickytani` GitHub account only
   after the owner reviews the changes and grants/uses write access. The
   connected GitHub integration in this session is read-only.

## Evidence index

- Project setup/dependencies: `pyproject.toml`
- Current M4 code/tests: `finguard/agent/orchestrator.py`,
  `tests/unit/test_bounded_orchestration.py`,
  `docs/M4-BOUNDED-ORCHESTRATION.md`
- Core architecture and constraints: `docs/architecture.md`,
  `docs/INVARIANTS.md`, `docs/MASTER_ROADMAP.md`
- Money and migration: `finguard/money.py`,
  `finguard/core/transaction.py`,
  `docs/runbooks/migrate-legacy-money.md`
- Historical evaluation and product positioning: `README.md`,
  `docs/quantitative-evaluation.md`, `docs/product-gap-report.md`
- GitHub identity/repository: `https://github.com/hickytani/finCLI`
