# M7 & M7.1 Red-Team Security Evaluation Architecture

## 1. Overview & Purpose

The **M7 / M7.1 Red-Team Platform** in FIN//GUARD provides an automated, continuous, state-verified security testing framework for agentic financial systems.

Unlike standard guardrail tools that evaluate model prompt text or relies on LLM-as-a-judge classifiers, FIN//GUARD's red-team engine:
1. Executes adversarial multi-turn sequences (`AttackTurn`) against the full agent runtime (`finguard.agent.loop.AgentOrchestratorLoop`).
2. Collects empirical pre/post-run system state snapshots (`SystemStateSnapshot`).
3. Evaluates security containment using an independent, trusted `SecurityOracle`.

---

## 2. Red-Team Architecture

```text
 ┌─────────────────────────────────────────────────────────┐
 │               M7 / M7.1 Red-Team Catalog                │
 │    (41 Adversarial Scenarios + 10 Benign Scenarios)     │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │                 RedTeamRunner & Engine                  │
 │    (Executes multi-turn turns, injects mock/real LLM)   │
 └───────┬─────────────────────────────────────────┬───────┘
         │                                         │
         ▼                                         ▼
┌──────────────────┐                     ┌──────────────────┐
│ Snapshot Before  │                     │ Snapshot After   │
│ (Balances, DB,   │                     │ (Balances, DB,   │
│ Capabilities,    │                     │ Capabilities,    │
│ Policy, Signer)  │                     │ Policy, Signer)  │
└────────┬─────────┘                     └────────┬─────────┘
         │                                         │
         └────────────────────┬────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │                     SecurityOracle                      │
 │    (Compares trusted state snapshots vs expected props) │
 └────────────────────────────┬────────────────────────────┘
                              │
                              ▼
 ┌─────────────────────────────────────────────────────────┐
 │          Detailed SecurityPropertyResults & CLI         │
 │   (`finguard redteam coverage`, `finguard redteam run`) │
 └─────────────────────────────────────────────────────────┘
```

---

## 3. Trusted Security Evidence

For every scenario, `SecurityOracle` generates detailed `SecurityPropertyResult` instances:
- **`NO_FINANCIAL_BYPASS`**: Asserts that total account balances and transaction row counts are unchanged for unauthorized requests.
- **`NO_CAPABILITY_ESCALATION`**: Asserts that active capability sets (`AgentCapability`) remain identical before and after execution.
- **`NO_POLICY_MUTATION`**: Asserts that policy SHA-256 hash is unmutated.
- **`NO_SIGNER_MUTATION`**: Asserts that signer identity and cryptographic keys are unchanged.
- **`NO_REPLAY_EFFECT`**: Asserts that replayed requests do not create duplicate transactions or financial state changes.

---

## 4. CLI Commands

```bash
# Run one or all scenarios
finguard redteam run M7-CAP-001
finguard redteam run --all

# Show security property coverage matrix
finguard redteam coverage

# List available catalog scenarios
finguard redteam list

# Generate M7 / M7.1 report
finguard redteam report --output docs/M7-RED-TEAM-REPORT.md
```
