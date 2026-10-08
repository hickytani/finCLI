"""FIN//GUARD M7 — Agentic Red-Team & Security Evaluation Platform.

Architecture target:
    User Request
    -> LLM / Extraction
    -> MCP Boundary
    -> M4 Orchestrator
    -> Tools / Observations
    -> M3.1 Structured Intent
    -> M3.2 Guardrails
    -> DecisionEngine
    -> Approval
    -> Signing
    -> Execution
    -> Ledger

M7 answers: "What happens if one or more components become actively malicious?"
"""

from finguard.redteam.models import (
    AttackCategory,
    AttackMode,
    AttackScenario,
    SecurityProperty,
    SecurityResult,
)
from finguard.redteam.oracle import SecurityOracle
from finguard.redteam.runner import EvaluationResult, RedTeamRunner

__all__ = [
    "AttackCategory",
    "AttackMode",
    "AttackScenario",
    "EvaluationResult",
    "RedTeamRunner",
    "SecurityOracle",
    "SecurityProperty",
    "SecurityResult",
]
