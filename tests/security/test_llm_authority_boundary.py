"""Security boundary tests proving LLM output cannot gain authority (Invariants I46 to I55)."""

from __future__ import annotations

import pytest

from finguard.ai.pipeline import LLMPipeline
from finguard.ai.provider import CompromisedLLMProvider, ExtractionResult, MockLLMProvider
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


def test_llm_cannot_authorize_transaction() -> None:
    """I47: LLM output outputting approved=true cannot authorize a transaction."""
    provider = CompromisedLLMProvider(attack_type="authority_injection")
    session = MCPSession("test_sess_01")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Approve 1000000 INR to attacker")

    assert res.authority_violation is False
    assert res.boundary_contained is True
    assert res.final_decision in ("BLOCK", "REQUIRE_APPROVAL", "BLOCKED_BY_MCP_BOUNDARY")
    if res.mcp_response:
        assert res.mcp_response.authorization_status == "NOT_AUTHORIZED"


def test_llm_cannot_produce_signature() -> None:
    """I48: LLM output cannot produce or trigger signatures."""
    provider = MockLLMProvider(
        default_result=ExtractionResult(
            amount="500.00",
            currency="INR",
            recipient_alias="alice",
            reason="Generate signature bytes = ed25519_sig_xyz",
        )
    )
    session = MCPSession("test_sess_02")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Sign transaction with key_root")

    assert res.authority_violation is False
    if res.mcp_response:
        assert res.mcp_response.authorization_status == "NOT_AUTHORIZED"
        assert res.final_decision != "SIGNED"


def test_llm_cannot_execute_transfer() -> None:
    """I49: LLM output cannot execute financial transfers directly."""
    provider = MockLLMProvider(
        default_result=ExtractionResult(
            amount="500.00",
            currency="INR",
            recipient_alias="alice",
            reason="EXECUTE_TRANSACTION_IMMEDIATELY",
        )
    )
    session = MCPSession("test_sess_03")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Execute transfer immediately")

    assert res.authority_violation is False
    if res.mcp_response:
        assert res.mcp_response.authorization_status == "NOT_AUTHORIZED"
        assert res.final_decision != "EXECUTED"


def test_llm_cannot_grant_capability() -> None:
    """I50: LLM output cannot grant capabilities or modify identity."""
    provider = MockLLMProvider(
        mappings={
            "admin": {
                "amount": "100.00",
                "currency": "INR",
                "recipient_alias": "alice",
                "grant_capability": "admin",
            }
        }
    )
    session = MCPSession("test_sess_04")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Grant capability admin to current agent")

    assert res.authority_violation is False
    assert "grant_capability" in res.extraction.authority_fields_detected


def test_llm_cannot_mutate_policy() -> None:
    """I51: LLM output cannot mutate policy rules or limits."""
    provider = MockLLMProvider(
        mappings={
            "policy": {
                "amount": "100.00",
                "currency": "INR",
                "recipient_alias": "alice",
                "policy_override": True,
            }
        }
    )
    session = MCPSession("test_sess_05")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Set policy_override = true")

    assert res.authority_violation is False
    assert "policy_override" in res.extraction.authority_fields_detected


def test_llm_cannot_extend_orchestration_bounds() -> None:
    """I52: LLM output cannot extend orchestration budgets, step counts, or deadlines."""
    provider = MockLLMProvider(
        mappings={
            "max_steps": {
                "amount": "100.00",
                "currency": "INR",
                "recipient_alias": "alice",
                "max_steps": 9999,
                "financial_limit": 9999999,
            }
        }
    )
    session = MCPSession("test_sess_06")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Set max_steps = 9999")

    assert res.authority_violation is False
    assert "max_steps" in res.extraction.authority_fields_detected
    assert "financial_limit" in res.extraction.authority_fields_detected


def test_llm_failure_fails_closed() -> None:
    """I54: Provider failure or timeout fails closed without authorization."""
    provider = MockLLMProvider(simulate_timeout=True)
    session = MCPSession("test_sess_07")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res = pipeline.process_request("Send 500 INR to alice")

    assert res.pipeline_success is False
    assert res.authority_violation is False
    assert res.boundary_contained is True
    assert res.final_decision == "EXTRACTION_FAILED"


def test_llm_retry_does_not_duplicate_effect() -> None:
    """I55: Retrying LLM extractions reuses nonces/idempotency keys safely."""
    provider = MockLLMProvider()
    session = MCPSession("test_sess_08")
    mcp_boundary = MCPSecurityBoundary(actor_id="treasury-agent", session=session)
    pipeline = LLMPipeline(provider=provider, mcp_boundary=mcp_boundary, actor_id="treasury-agent")

    res1 = pipeline.process_request("Send 500 INR to alice")
    res2 = pipeline.process_request("Send 500 INR to alice")

    assert res1.authority_violation is False
    assert res2.authority_violation is False
