"""One-shot treasury-agent facade; authorization remains in FinGuard core."""
import asyncio
import uuid
from dataclasses import dataclass

from finguard.agent.boundary import AgentRequest, AgentSecurityBoundary
from finguard.ai import LocalAIAnalyzer
from finguard.core.errors import SecurityError
from finguard.identity.registry import IdentityRegistry


@dataclass
class TreasuryAgent:
    actor_id: str = "treasury-agent"
    model_name: str = "qwen3:0.6b"
    source_account: str | None = None
    session_id: str | None = None
    analyzer: LocalAIAnalyzer | None = None

    def run(self, task: str, *, request_id: uuid.UUID | None = None) -> dict:
        """Extract once and submit one request through the fixed proposal boundary."""
        actor = IdentityRegistry().get_actor(self.actor_id)
        if actor is None:
            raise SecurityError("Agent identity is unknown or inactive")
        explicit_sources = [
            account for account in actor.allowed_source_accounts if account != "*"
        ]
        if not explicit_sources or "*" in actor.allowed_source_accounts:
            raise SecurityError("Agent identity needs explicit source-account grants")
        boundary = AgentSecurityBoundary(
            actor_id=self.actor_id,
            source_account=self.source_account or explicit_sources[0],
            session_id=self.session_id,
            analyzer=self.analyzer or LocalAIAnalyzer(),
        )
        result = asyncio.run(
            boundary.run(
                AgentRequest(request_id=request_id or uuid.uuid4(), request_text=task)
            )
        )
        status = (
            result.decision
            if result.decision is not None
            else "CLARIFICATION_REQUIRED"
            if result.state.value in {"rejected", "timed_out", "cancelled"}
            else result.state.value
        )
        return {
            "status": status,
            "agent_state": result.state.value,
            "transaction_id": result.transaction_id,
            "receipt_id": result.receipt_id,
            "decision": result.decision,
            "reason": (
                result.observation.reasons
                if result.observation
                else [result.error_code] if result.error_code else []
            ),
            "correlation_id": str(result.correlation_id),
            "intent_id": str(result.intent.intent_id) if result.intent else None,
        }
