# Architecture

`CLI / TreasuryAgent / FinGuardAgentClient -> DecisionEngine -> signed identity -> authority -> policy -> deterministic risk -> approval state -> decision receipt -> audit`.

The signing primitive remains downstream and is intentionally absent from both
the agent and SDK interfaces. AI and ML assessments are advisory only and may
never turn an authority/policy/replay failure into `ALLOW`.
