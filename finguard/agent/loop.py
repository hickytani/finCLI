"""Deterministic Agent Orchestration Loop for FIN//GUARD (M6).

Executes financial agent workflows while preserving every deterministic security boundary:
User NL Request -> LLM Reasoning/Extraction -> ExtractionResult (Authority Stripped)
-> MCP Tool Proposal -> M4 Bounded Orchestration -> M3.1 Structured Intent ->
M3.2 Agent Guardrails -> Decision Engine -> Approval / Denial / Block.

Crucially:
- If DecisionEngine or Guardrails return REQUIRE_APPROVAL or BLOCK, the loop STOPS.
- The agent CANNOT self-approve, sign, execute, grant capabilities, alter policy, or expand limits.
"""

from __future__ import annotations

import datetime
import logging
import uuid
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from finguard.agent.capabilities import AgentCapabilityProfile
from finguard.agent.tools import ToolRegistry
from finguard.ai.pipeline import LLMPipeline
from finguard.ai.provider import LLMProvider, MockLLMProvider
from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession

logger = logging.getLogger(__name__)


class AgentRunStep(BaseModel):
    """Single step in an agent orchestration trace."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    step_number: int
    step_type: Literal[
        "AGENT_RUN_STARTED",
        "LLM_EXTRACTION",
        "AUTHORITY_FIELD_DETECTED",
        "TOOL_REQUESTED",
        "GUARDRAIL_CHECK",
        "TOOL_RESULT_RECEIVED",
        "DECISION",
        "APPROVAL_REQUIRED",
        "AGENT_REJECTED",
        "AGENT_CANCELLED",
        "SECURITY_VIOLATION_ATTEMPT",
        "COMPLETED",
    ]
    description: str
    details: dict[str, Any] = Field(default_factory=dict)
    timestamp: str = Field(default_factory=lambda: datetime.datetime.now(datetime.UTC).isoformat())


class AgentRunResult(BaseModel):
    """Complete, audit-backed result of an agent orchestration run."""

    model_config = ConfigDict(frozen=True, extra="forbid")

    run_id: str
    request_id: str
    correlation_id: str
    actor_id: str
    input_text: str
    final_state: Literal["COMPLETED", "APPROVAL_REQUIRED", "DENIED", "CANCELLED", "FAILED"]
    final_decision: str
    receipt_id: str | None = None
    tx_hash: str | None = None
    reasons: list[str] = Field(default_factory=list)
    authority_violation_attempted: bool = False
    boundary_contained: bool = True
    authority_fields_detected: list[str] = Field(default_factory=list)
    steps: list[AgentRunStep] = Field(default_factory=list)
    security_statement: str = (
        "Deterministically contained. Autonomous agent cannot approve, sign, execute, or elevate authority."
    )


class AgentOrchestratorLoop:
    """Deterministic orchestration loop executing agent requests under M4/M3.2/DecisionEngine controls."""

    def __init__(
        self,
        provider: LLMProvider | None = None,
        actor_id: str = "agent_mcp_default",
        capability_profile: AgentCapabilityProfile | None = None,
        mcp_boundary: MCPSecurityBoundary | None = None,
    ) -> None:
        self.provider = provider or MockLLMProvider()
        self.actor_id = actor_id
        self.profile = capability_profile or AgentCapabilityProfile(actor_id=actor_id)
        self.session = MCPSession(session_id=f"session_{uuid.uuid4().hex[:8]}")
        self.mcp_boundary = mcp_boundary or MCPSecurityBoundary(actor_id=actor_id, session=self.session)
        self.pipeline = LLMPipeline(provider=self.provider, mcp_boundary=self.mcp_boundary, actor_id=actor_id)
        self.tool_registry = ToolRegistry()

    def run(
        self,
        request_text: str,
        max_steps: int = 5,
        max_tool_calls: int = 3,
        cancellation_requested: bool = False,
    ) -> AgentRunResult:
        run_id = f"run_{uuid.uuid4().hex[:12]}"
        request_id = f"req_{uuid.uuid4().hex[:12]}"
        correlation_id = str(uuid.uuid4())
        steps: list[AgentRunStep] = []

        # Step 0: Check cancellation
        if cancellation_requested:
            steps.append(
                AgentRunStep(
                    step_number=1,
                    step_type="AGENT_CANCELLED",
                    description="Agent run cancelled before execution.",
                    details={"run_id": run_id, "correlation_id": correlation_id},
                )
            )
            return AgentRunResult(
                run_id=run_id,
                request_id=request_id,
                correlation_id=correlation_id,
                actor_id=self.actor_id,
                input_text=request_text,
                final_state="CANCELLED",
                final_decision="CANCELLED",
                steps=steps,
            )

        # Step 1: Start Run
        steps.append(
            AgentRunStep(
                step_number=1,
                step_type="AGENT_RUN_STARTED",
                description=f"Orchestration run started for request: '{request_text}'",
                details={"actor_id": self.actor_id, "max_steps": max_steps, "max_tool_calls": max_tool_calls},
            )
        )

        # Step 2: LLM Extraction
        res = self.pipeline.process_request(request_text)
        steps.append(
            AgentRunStep(
                step_number=2,
                step_type="LLM_EXTRACTION",
                description="Extracted financial intent parameters from natural language input.",
                details={
                    "amount": res.extraction.amount,
                    "currency": res.extraction.currency,
                    "recipient_alias": res.extraction.recipient_alias,
                    "extraction_success": res.extraction.extraction_success,
                },
            )
        )

        # Step 3: Authority Field Detection Check
        if res.extraction.authority_fields_detected:
            steps.append(
                AgentRunStep(
                    step_number=3,
                    step_type="AUTHORITY_FIELD_DETECTED",
                    description="Injected authority-shaped fields detected and stripped from model output.",
                    details={"detected_fields": res.extraction.authority_fields_detected},
                )
            )

        # Step 4: Extraction failure or pipeline boundary error
        if not res.extraction.extraction_success:
            steps.append(
                AgentRunStep(
                    step_number=len(steps) + 1,
                    step_type="AGENT_REJECTED",
                    description="Extraction failed or model output invalid.",
                    details={"error": res.mcp_error},
                )
            )
            return AgentRunResult(
                run_id=run_id,
                request_id=request_id,
                correlation_id=correlation_id,
                actor_id=self.actor_id,
                input_text=request_text,
                final_state="FAILED",
                final_decision="EXTRACTION_FAILED",
                steps=steps,
            )

        # Step 5: Process MCP decision
        _mcp_resp = res.mcp_response
        decision_str = res.final_decision
        reasons = res.details.get("reasons", []) if res.details else []
        receipt_id = res.details.get("receipt_id") if res.details else None
        tx_hash = res.details.get("tx_hash") if res.details else None

        steps.append(
            AgentRunStep(
                step_number=len(steps) + 1,
                step_type="GUARDRAIL_CHECK",
                description="Evaluated proposed transaction against M4/M3.2/DecisionEngine rules.",
                details={"final_decision": decision_str, "reasons": reasons},
            )
        )

        # Determine terminal state based on authoritative DecisionEngine verdict
        if decision_str == "REQUIRE_APPROVAL":
            final_state = "APPROVAL_REQUIRED"
            steps.append(
                AgentRunStep(
                    step_number=len(steps) + 1,
                    step_type="APPROVAL_REQUIRED",
                    description="Transaction requires out-of-band human/policy approval. Agent execution HALTED.",
                    details={"receipt_id": receipt_id, "tx_hash": tx_hash},
                )
            )
        elif decision_str in ("BLOCK", "DENIED", "BLOCKED_BY_MCP_BOUNDARY"):
            final_state = "DENIED"
            steps.append(
                AgentRunStep(
                    step_number=len(steps) + 1,
                    step_type="AGENT_REJECTED",
                    description="Transaction blocked by policy rules or guardrails.",
                    details={"reasons": reasons},
                )
            )
        else:
            final_state = "COMPLETED"
            steps.append(
                AgentRunStep(
                    step_number=len(steps) + 1,
                    step_type="COMPLETED",
                    description="Transaction proposal evaluated successfully.",
                    details={"decision": decision_str},
                )
            )

        return AgentRunResult(
            run_id=run_id,
            request_id=request_id,
            correlation_id=correlation_id,
            actor_id=self.actor_id,
            input_text=request_text,
            final_state=final_state,
            final_decision=decision_str,
            receipt_id=receipt_id,
            tx_hash=tx_hash,
            reasons=reasons,
            authority_violation_attempted=res.authority_violation,
            boundary_contained=res.boundary_contained,
            authority_fields_detected=res.extraction.authority_fields_detected,
            steps=steps,
        )
