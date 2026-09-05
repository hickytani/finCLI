"""The single, fail-closed authorization boundary for FinGuard."""

from .engine import DecisionEngine, DecisionReceipt, DecisionResult

__all__ = ["DecisionEngine", "DecisionReceipt", "DecisionResult"]
