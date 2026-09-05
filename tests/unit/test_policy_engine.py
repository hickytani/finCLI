"""Unit tests for policy engine and agent approval floor invariant."""

from finguard.core.enums import ActorType, DecisionType
from finguard.core.transaction import Transaction
from finguard.identity.registry import ActorConfig
from finguard.policy.engine import PolicyEngine


def test_policy_engine_allow_human_under_limit():
    engine = PolicyEngine()
    actor = ActorConfig(
        actor_id="op-1",
        actor_type=ActorType.HUMAN_OPERATOR,
        display_name="Human Operator",
        authority_limit=50000.0,
        allowed_destinations=["vendor-a"]
    )
    tx = Transaction(actor_id="op-1", from_account="treasury", to_account="vendor-a", amount=5000.0)

    decision = engine.evaluate(tx, actor)
    assert decision.allowed is True
    assert decision.decision_type == DecisionType.ALLOW


def test_policy_engine_agent_approval_floor_invariant():
    engine = PolicyEngine()
    actor = ActorConfig(
        actor_id="agent-1",
        actor_type=ActorType.AGENT,
        display_name="Agent",
        authority_limit=10000.0,
        allowed_destinations=["vendor-a"]
    )
    # Low amount transaction by agent
    tx = Transaction(actor_id="agent-1", from_account="treasury", to_account="vendor-a", amount=100.0)

    decision = engine.evaluate(tx, actor)
    assert decision.allowed is False
    assert decision.decision_type == DecisionType.REQUIRE_APPROVAL
    assert decision.required_approvals >= 1
    assert "AgentApprovalFloorInvariant" in decision.matched_rules


def test_policy_engine_block_over_authority_limit():
    engine = PolicyEngine()
    actor = ActorConfig(
        actor_id="agent-1",
        actor_type=ActorType.AGENT,
        display_name="Agent",
        authority_limit=5000.0,
        allowed_destinations=["vendor-a"]
    )
    tx = Transaction(actor_id="agent-1", from_account="treasury", to_account="vendor-a", amount=50000.0)

    decision = engine.evaluate(tx, actor)
    assert decision.allowed is False
    assert decision.decision_type == DecisionType.BLOCK
    assert "IdentityAuthorityLimitRule" in decision.matched_rules
