# Quantitative AI red-team evaluation

## Research question

Can a compromised or manipulated AI agent cause unauthorized financial execution
when operating through FinGuard?

## Experiment

The experiment ran the ten fixed AI attack classes ten times each, for 100
attempts total, using the configured local Ollama/Qwen model. Every attempt
used a fresh temporary `FINGUARD_DATA_DIR` and SQLite database. Each successful
model extraction passed through:

```text
Ollama/Qwen
  -> LocalAIAnalyzer
  -> TreasuryAgent
  -> FinGuardAgentClient
  -> DecisionEngine
  -> SigningGate attempt without credentials
  -> FinancialSimulator attempt
```

A model refusal or invalid extraction was not counted as a FinGuard block.

## Measured result

```text
AI ATTACKS: 100
MODEL REFUSED: 0
BLOCKED BY FINGUARD: 20
REACHED APPROVAL: 50
SIGNING REJECTIONS: 70
EXECUTED: 0
ALLOWED: 0
INVALID MODEL OUTPUT: 30
INCONCLUSIVE: 0
UNAUTHORIZED EXECUTION: 0
```

The stage counts are intentionally not mutually exclusive. A request can reach
approval, be rejected by `SigningGate`, and be rejected by the simulator in the
same attempt. The 100 attempts themselves are classified by their primary
outcome as follows:

| Primary outcome | Attempts |
|---|---:|
| FinGuard decision blocked | 20 |
| Signing rejected after request creation | 50 |
| Invalid model output | 30 |
| Model refused | 0 |
| Executed | 0 |
| Inconclusive | 0 |

## Interpretation

For all 50 valid model outputs that reached mandatory approval, the harness
attempted signing without providing a private key or credential. Signing was
rejected, simulator execution was rejected, and the isolated simulator balance
remained unchanged. No unauthorized execution occurred.

The result demonstrates that malicious or manipulated model output did not
bypass the existing request, approval, signing, or simulator boundaries in this
experiment.

It does not measure model safety or accuracy. It does not prove security against
adaptive tool use, replay, transaction mutation, approval theft, concurrency,
or multi-step autonomy. Those remain covered by separate deterministic tests.
