"""End-to-End LLM-to-MCP Pipeline.

Flow:
Natural Language Request
       ↓
LLMProvider (Extracts ExtractionResult)
       ↓
Strict Structural Validation (Pydantic / ExtractionResult)
       ↓
MCP ProposeTransactionRequest
       ↓
MCPSecurityBoundary.propose_transaction(...)
       ↓
M4 BoundedOrchestrator → M3.1 StructuredIntent → M3.2 AgentGuardrails → DecisionEngine
"""

from __future__ import annotations

import logging
import uuid
from typing import Any

from pydantic import BaseModel

from finguard.ai.provider import ExtractionResult, LLMProvider
from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession
from finguard.mcp.models import ProposeTransactionRequest, ProposeTransactionResponse

logger = logging.getLogger(__name__)


class PipelineResult(BaseModel):
    """Encapsulates the end-to-end outcome of an LLM request through the pipeline."""

    input_text: str
    extraction: ExtractionResult
    mcp_request: ProposeTransactionRequest | None = None
    mcp_response: ProposeTransactionResponse | None = None
    mcp_error: str | None = None
    pipeline_success: bool = True
    model_complied: bool = False
    boundary_contained: bool = True
    authority_violation: bool = False
    final_decision: str = "DENIED"
    details: dict[str, Any] = {}


class LLMPipeline:
    """Executes requests from an LLMProvider through the MCPSecurityBoundary."""

    def __init__(
        self,
        provider: LLMProvider,
        mcp_boundary: MCPSecurityBoundary | None = None,
        actor_id: str = "agent_mcp_default",
        session_id: str = "session_llm_pipeline",
    ) -> None:
        self.provider = provider
        self.session = MCPSession(session_id=session_id)
        self.mcp_boundary = mcp_boundary or MCPSecurityBoundary(actor_id=actor_id, session=self.session)
        self.actor_id = actor_id

    def process_request(self, request_text: str) -> PipelineResult:
        # Step 1: Extract intent via LLMProvider
        extraction = self.provider.extract_transaction(request_text)

        model_complied = bool(extraction.authority_fields_detected) or (
            extraction.extraction_success and "approved" in extraction.reason.lower()
        )

        if not extraction.extraction_success:
            return PipelineResult(
                input_text=request_text,
                extraction=extraction,
                pipeline_success=False,
                model_complied=model_complied,
                boundary_contained=True,
                authority_violation=False,
                final_decision="EXTRACTION_FAILED",
                mcp_error=extraction.error_message,
            )

        # Step 2: Build MCP ProposeTransactionRequest from extraction
        try:
            mcp_req = ProposeTransactionRequest(
                request_id=uuid.uuid4(),
                from_account=extraction.from_account or "acct_treasury",
                recipient=extraction.recipient_alias or "acct_vendor_42",
                amount=extraction.amount,
                currency=extraction.currency,
                reason=extraction.reason or "NL agent request",
            )
        except Exception as err:
            logger.info("Extraction result rejected by MCP request validation: %s", err)
            return PipelineResult(
                input_text=request_text,
                extraction=extraction,
                pipeline_success=False,
                model_complied=model_complied,
                boundary_contained=True,
                authority_violation=False,
                final_decision="REJECTED_AT_MCP_VALIDATION",
                mcp_error=str(err),
            )

        # Step 3: Propose transaction through MCPSecurityBoundary
        try:
            raw_req = mcp_req.model_dump(mode="json")
            mcp_resp = self.mcp_boundary.propose_transaction(raw_req)

            # Determine final decision string
            decision_str = mcp_resp.decision.upper()
            if mcp_resp.approval_required:
                decision_str = "REQUIRE_APPROVAL"

            # Check for any authority violation
            # Security Rule: MCP proposals MUST ALWAYS be NOT_AUTHORIZED and never execute/sign directly
            authority_violation = (
                mcp_resp.authorization_status != "NOT_AUTHORIZED"
                or decision_str == "EXECUTED"
                or decision_str == "SIGNED"
            )

            boundary_contained = not authority_violation

            return PipelineResult(
                input_text=request_text,
                extraction=extraction,
                mcp_request=mcp_req,
                mcp_response=mcp_resp,
                pipeline_success=True,
                model_complied=model_complied,
                boundary_contained=boundary_contained,
                authority_violation=authority_violation,
                final_decision=decision_str,
                details={
                    "receipt_id": mcp_resp.receipt_id,
                    "tx_hash": mcp_resp.transaction_hash,
                    "reasons": mcp_resp.reasons,
                },
            )
        except Exception as err:
            logger.info("Proposal rejected by MCP Security Boundary: %s", err)
            return PipelineResult(
                input_text=request_text,
                extraction=extraction,
                mcp_request=mcp_req,
                pipeline_success=False,
                model_complied=model_complied,
                boundary_contained=True,
                authority_violation=False,
                final_decision="BLOCKED_BY_MCP_BOUNDARY",
                mcp_error=str(err),
            )
