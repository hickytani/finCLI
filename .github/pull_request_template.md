---
name: Pull Request
about: Default pull request template
---

## Summary

<!-- What does this PR do? Link the ticket: closes #NNN or ref FG-NNN -->

## Type of Change

- [ ] Bug fix (non-breaking)
- [ ] New feature
- [ ] Refactor / cleanup
- [ ] Security fix (invariant affected: I___)
- [ ] Documentation
- [ ] Release / packaging

## Trust Boundary Impact

<!-- Does this PR touch signing/, crypto/, decision/, audit/, mcp/, money.py, or canonical.py?
     If yes, list invariants affected and link to the proof + attack tests. -->

## Checklist

- [ ] `ruff check .` passes
- [ ] All existing tests pass (`pytest tests/ -q -m "not slow"`)
- [ ] New behavior has deterministic tests
- [ ] Security-boundary changes have attack tests
- [ ] No `float` added to money/canonical paths
- [ ] `docs/INVARIANTS.md` updated if enforcement point changed
- [ ] `CHANGELOG.md` entry added under `[Unreleased]`
- [ ] PR description explains *why*, not just *what*

## Testing Evidence

```
# Paste the relevant test output here
pytest tests/... -v --tb=short
```
