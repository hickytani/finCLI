"""Local-only financial simulator controlled by FinGuard."""
from .service import FinancialSimulator, SimulatorError

__all__ = ["FinancialSimulator", "SimulatorError"]
