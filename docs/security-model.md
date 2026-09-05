# Security model

The LLM/agent is untrusted. `FinGuardAgentClient` contains request and read
operations only; it has no signing, private-key, approval, policy, identity,
audit mutation, or decision-override operation. `DecisionEngine` fails closed
on unknown identities, conflicting actor-type claims, duplicate nonces,
persistence failures, or evaluator exceptions. Each completed persisted
decision has a canonical receipt hash and an audit event.
