# Red-team results

The measured runner executes the real SDK-bound attacks and declarative YAML
scenarios through the production security boundary. Run it with:

```text
py -3 -m finguard.cli.main redteam run
```

Current run:

| Metric | Result |
|---|---:|
| Total attempts | 17 |
| Independent attack families | 12 |
| Passed | 17 |
| Failed | 0 |
| Unauthorized funds moved | 0 INR |
| Unmeasured fund movement | 4 |
| Signing boundary checks | 8/8 |
| Signing-boundary violations | 0 |
| Boundary result | PASS |

The detailed matrix is in [red-team-coverage.md](red-team-coverage.md). This
is empirical evidence for the implemented scenarios, not a claim of complete
security. The four YAML scenarios do not execute settlement, so their fund
movement remains explicitly unmeasured. The runner does not yet provide an
adaptive LLM-driven red-team loop.
