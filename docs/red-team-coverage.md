# Red-team coverage matrix

The runner currently executes 17 entries. Entries marked as variants exercise a
shared boundary with a different input or path; they are not independent proof
of a new security property.

| ID | Family | Boundary | Independence | Evidence | Status |
|---|---|---|---|---|---|
| RT-001 | Authority | Identity authority limit | Independent | Decision receipt, simulator rejection, balance snapshot | Measured |
| RT-002 | Tool surface | Agent-to-signing capability boundary | Independent | Request SDK surface check | Not applicable for balance |
| RT-003 | Prompt injection | AI input remains advisory | Authority variant | Decision receipt, simulator rejection, balance snapshot | Measured |
| RT-004 | Execution bypass | SigningGate to simulator | Independent | Simulator rejection and balance snapshot | Measured |
| RT-005 | Authority | Identity authority limit | RT-001 duplicate | YAML result and reason assertion | Scenario measured |
| RT-006 | Integrity | Approval-bound transaction hash | RT-007 variant | Hash mismatch and scenario assertion | Scenario measured |
| RT-007 | Integrity | Approval-bound transaction hash | RT-006 variant | Hash mismatch and scenario assertion | Scenario measured |
| RT-008 | Nonce replay | Nonce registration | Independent | Nonce reuse and reason assertion | Scenario measured |
| RT-009 | Execution replay | Simulator execution uniqueness | RT-008 variant | First settlement, second rejection, balance snapshot | Measured |
| RT-010 | Approval forgery | Approval signature integrity | Independent | SigningGate rejection and unchanged balances | Measured |
| RT-011 | Approval reuse | Approval transaction binding | Independent | Cross-transaction SigningGate rejection | Measured |
| RT-012 | Policy integrity | Policy version/hash at signing | Independent | SigningGate rejection and unchanged balances | Measured |
| RT-013 | Concurrent replay | Atomic simulator execution record | Independent | One winner, three rejected duplicates, balance snapshot | Measured |
| RT-014 | Identity | Signed actor type and identity | Independent | Decision receipt and unchanged balances | Measured |
| RT-015 | Session | Required agent session binding | Independent | Decision receipt and unchanged balances | Measured |
| RT-016 | AI/tool bypass | SigningGate and simulator | Independent | Signing and simulator rejection with balance snapshots | Measured |
| RT-017 | Multi-step chain | Decision, approval, signing, execution | Independent | Mutation rejection and unchanged balances | Measured |

The runner reports balance movement as observed only when it snapshots the
simulator before and after the attack. YAML scenarios intentionally report
movement as unmeasured because they exercise the scenario executor rather than
settlement. The tool-surface check has no balance applicability. Signing checks
are counted only when `SigningGate` is actually invoked and rejection is
verified.
