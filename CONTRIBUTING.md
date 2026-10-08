# Contributing to FIN//GUARD

Thank you for your interest in contributing. FIN//GUARD is a security-research
project; contributions must meet the same standard as the existing code:
**"would a staff engineer at a payments/security company approve this PR without
rework?"**

## Before You Start

- Read [`docs/CURRENT-ARCHITECTURE.md`](docs/CURRENT-ARCHITECTURE.md) and
  [`docs/INVARIANTS.md`](docs/INVARIANTS.md).
- Read [`SECURITY.md`](SECURITY.md) if your change touches a trust boundary.
- Check open issues for existing work before starting.

## Development Setup

```bash
# Clone
git clone https://github.com/hickytani/finCLI.git
cd finCLI

# Create a virtual environment (Python >= 3.12)
python -m venv .venv
source .venv/bin/activate   # Windows: .venv\Scripts\activate

# Install in editable mode with dev extras
pip install -e ".[dev]"

# Verify baseline
pytest tests/ -q --tb=short -m "not slow"
```

## Branching

| Branch pattern | Purpose |
|----------------|---------|
| `main` | Stable, always green |
| `fg-NNN-*` | Ticket-specific work |
| `m{N}-*` | Milestone work |

Open a draft PR early; force-push freely until you mark it Ready for Review.

## Commit Style

Follow [Conventional Commits](https://www.conventionalcommits.org/):

```
feat(money): add Money.from_decimal() with exact precision check
fix(signing): reject NaN via explicit isfinite check
test(audit): add ledger gap-free property test
docs(invariants): update I7 enforcement point for sequenced ledger
```

Reference the ticket: `closes #123` or `ref FG-201`.

## Code Standards

- **Style**: `ruff check .` must pass (zero warnings). Run `ruff check --fix .` before pushing.
- **Types**: Use type annotations on all public functions.
- **Security**: See the invariant list (I1–I14) in `docs/INVARIANTS.md`. Any
  change that touches a trust boundary must:
  1. Cite the invariant it affects.
  2. Include a deterministic (non-LLM) test that proves the invariant holds.
  3. Include an attack test that proves the invariant blocks the relevant threat.
- **Money**: Never use `float` in money or canonical paths. The AST gate
  (`test_no_float_money`) will fail your build. Add to the allowlist only with
  a documented justification comment.
- **Fail-closed**: Any new code in `decision/`, `signing/`, `audit/`, or `mcp/`
  must fail closed on exception (block, not allow).

## Testing

```bash
# Fast unit/regression/security/property suite
pytest tests/unit/ tests/regression/ tests/security/ tests/property/ -v

# Attack simulation
pytest tests/attack/ -v -m attack

# With coverage (gate: 71% branch)
pytest tests/ --cov=finguard --cov-branch --cov-fail-under=71 -m "not slow"
```

Tests marked `slow` require a running Ollama instance and are skipped in CI.

## Pull Request Checklist

- [ ] `ruff check .` passes.
- [ ] All existing tests pass.
- [ ] New/changed behavior has deterministic tests.
- [ ] Security-boundary changes have attack tests.
- [ ] No `float` added to money/canonical paths (AST gate).
- [ ] `docs/INVARIANTS.md` updated if an enforcement point changed.
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`.
- [ ] PR description explains *why*, not just *what*.

## Security Vulnerabilities

Do **not** file public issues for security bugs. See [`SECURITY.md`](SECURITY.md).

## License

By contributing, you agree that your contributions are licensed under the
[MIT License](LICENSE).
