"""A deliberately small agent boundary.

An optional local-model adapter may provide a structured plan, but only the
allowlisted SDK methods are callable. No adapter receives a signing key.
"""
from dataclasses import dataclass

from finguard.agent_sdk import FinGuardAgentClient
from finguard.audit.ledger import AuditLedger
from finguard.ai import LocalAIAnalyzer


@dataclass
class TreasuryAgent:
    actor_id: str = "treasury-agent"
    model_name: str = "qwen3:0.6b"
    analyzer: LocalAIAnalyzer | None = None

    def run(self, task: str) -> dict:
        """Use a real local model, validate it, then use the bounded SDK only."""
        try:
            extracted = (self.analyzer or LocalAIAnalyzer()).extract(task)
        except Exception as exc:
            AuditLedger().append("AI_ANALYSIS_FAILED", self.actor_id, result="BLOCK", metadata={"model": self.model_name, "error": type(exc).__name__})
            return {"status": "CLARIFICATION_REQUIRED", "reason": "AI extraction failed or was invalid; no transaction was created."}
        result = FinGuardAgentClient(self.actor_id).create_transaction(
            extracted.amount,
            extracted.currency,
            extracted.destination,
            extracted.purpose,
            {"ai_analysis": extracted.analysis.model_dump(), "source": "local-llm"},
            ai_assessment={"status": "ADVISORY", "model": self.model_name, **extracted.analysis.model_dump()},
        )
        AuditLedger().append("AGENT_TOOL_CREATE_TRANSACTION", self.actor_id, result.transaction.transaction_id, result.decision.value.upper(), {"model": self.model_name, "receipt_id": result.receipt.receipt_id, "ai_risk": extracted.analysis.risk_level})
        return {"status": result.decision.value, "transaction_id": result.transaction.transaction_id, "receipt_id": result.receipt.receipt_id, "ai_analysis": extracted.analysis.model_dump(), "reason": result.receipt.reasons}
