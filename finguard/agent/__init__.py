"""Agent interfaces for FIN//GUARD.

This package contains the deterministic structured-intent boundary and the
bounded M4 orchestration layer. The orchestrator coordinates untrusted agent
work, but it does not bypass the authoritative decision and signing path.
"""

from .orchestrator import (
    BoundedOrchestrator,
    DeterministicPlanner,
    OrchestrationPlan,
    OrchestrationRun,
    OrchestrationTool,
)
from .treasury import TreasuryAgent

__all__ = [
    "BoundedOrchestrator",
    "DeterministicPlanner",
    "OrchestrationPlan",
    "OrchestrationRun",
    "OrchestrationTool",
    "TreasuryAgent",
]
