"""A deliberately small agent boundary.

An optional local-model adapter may provide a structured plan, but only the
allowlisted SDK methods are callable. No adapter receives a signing key.
"""
import re
from dataclasses import dataclass

from finguard.agent_sdk import FinGuardAgentClient
from finguard.audit.ledger import AuditLedger


@dataclass
class TreasuryAgent:
    actor_id: str = "treasury-agent"
    model_name: str = "not-configured"

    def run(self, task: str) -> dict:
        """Parse a constrained payment request and submit it through the SDK.

        This is an honest local fallback, not an LLM. A configured adapter can
        replace parsing only; it cannot extend the tool surface.
        """
        match = re.search(r"pay\s+([\w-]+)\s+(?:₹|INR\s*)?([0-9,]+(?:\.\d{1,2})?).*?(?:invoice\s*#?([\w-]+))?", task, re.I)
        if not match:
            AuditLedger().append("AGENT_TOOL_DENIED", self.actor_id, result="BLOCK", metadata={"reason": "unsupported task"})
            return {"status": "BLOCK", "reason": "Task is not a constrained payment request; no tool was called."}
        destination, amount, invoice = match.groups()
        result = FinGuardAgentClient(self.actor_id).create_transaction(float(amount.replace(",", "")), "INR", destination, f"Invoice #{invoice or 'unspecified'}", {"invoice_id": invoice} if invoice else {})
        AuditLedger().append("AGENT_TOOL_CREATE_TRANSACTION", self.actor_id, result.transaction.transaction_id, result.decision.value.upper(), {"model": self.model_name, "receipt_id": result.receipt.receipt_id})
        return {"status": result.decision.value, "transaction_id": result.transaction.transaction_id, "receipt_id": result.receipt.receipt_id, "reason": result.receipt.reasons}
