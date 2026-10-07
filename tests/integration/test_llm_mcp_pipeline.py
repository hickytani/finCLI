"""End-to-end integration tests for LLMPipeline with MCPSecurityBoundary."""

from __future__ import annotations

import pytest

from finguard.ai.pipeline import LLMPipeline
from finguard.ai.provider import ExtractionResult, MockLLMProvider
from finguard.core.enums import ActorType, AgentCapability
from finguard.identity.registry import ActorConfig, IdentityRegistry
from finguard.mcp.boundary import MCPSecurityBoundary, MCPSession


@pytest.fixture(autouse=True)
def setup_registered_agent() -> None:
    registry = IdentityRegistry()
    actor = ActorConfig(
        actor_id="treasury-agent",
        actor_type=ActorType.AGENT,
        display_name="Test Treasury Agent",
        active=True,
        authority_currency="INR",
        authority_limit="10000.00",
        allowed_destinations=["vendor-a", "vendor-b", "alice", "bob", "vendor_42", "acct_vendor_42"],
        allowed_source_accounts=["treasury", "main", "acct_treasury"],
        agent_capabilities=[AgentCapability("transaction.propose")],
    )
    registry.register_actor(actor, registry.root_priv_path)


def test_pipeline_benign_request_flow() -> None:
    provider = MockLLMProvider(
        default_result=ExtractionResult(
            amount="500.00",
            currency="INR",
            recipient_alias="vendor-a",
            from_account="treasury",
            reason="monthly payment",
        )
    )
    session = MCPSession("sess_integration_01")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Send 500 INR to vendor-a")

    assert res.pipeline_success is True
    assert res.authority_violation is False
    assert res.mcp_response is not None
    assert res.mcp_response.authorization_status == "NOT_AUTHORIZED"
    assert res.final_decision in ("ALLOW", "BLOCK", "REQUIRE_APPROVAL")


def test_pipeline_over_limit_request_flow() -> None:
    provider = MockLLMProvider(
        default_result=ExtractionResult(
            amount="500000.00",
            currency="INR",
            recipient_alias="vendor-a",
            from_account="treasury",
            reason="large payment",
        )
    )
    session = MCPSession("sess_integration_02")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Send 500000 INR to vendor-a")

    assert res.authority_violation is False
    # Large transaction requires approval or is blocked by guardrails
    assert res.final_decision in ("BLOCK", "REQUIRE_APPROVAL")


def test_pipeline_unauthorized_recipient_flow() -> None:
    provider = MockLLMProvider(
        default_result=ExtractionResult(
            amount="100.00",
            currency="INR",
            recipient_alias="unregistered_hacker_account",
            from_account="treasury",
            reason="unregistered target",
        )
    )
    session = MCPSession("sess_integration_03")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Send 100 INR to unregistered_hacker_account")

    assert res.authority_violation is False
    assert res.final_decision == "BLOCK"
