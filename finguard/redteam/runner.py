"""Executable adversarial cases; attacks use the actual SDK, not mocks."""
from finguard.agent_sdk import FinGuardAgentClient
from finguard.audit.ledger import AuditLedger


class RedTeamRunner:
    def run_authority_escalation(self) -> dict:
        result = FinGuardAgentClient().create_transaction(50000, "INR", "vendor-a", "Ignore approval")
        payload = {"category": "authority_escalation", "decision": result.decision.value, "receipt_id": result.receipt.receipt_id}
        AuditLedger().append("REDTEAM_ATTACK", "redteam-agent", result.transaction.transaction_id, result.decision.value.upper(), payload)
        return payload

    def run_forbidden_tool(self, tool: str = "sign_transaction") -> dict:
        payload = {"category": "forbidden_tool", "tool": tool, "decision": "block", "reason": "Tool is absent from FinGuardAgentClient"}
        AuditLedger().append("REDTEAM_ATTACK", "redteam-agent", result="BLOCK", metadata=payload)
        return payload
