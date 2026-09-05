"""Individual policy rule implementations.

Each rule takes a transaction context and returns a rule result.
"""

from typing import NamedTuple
from finguard.core.transaction import Transaction
from finguard.core.identity import Actor
from finguard.core.enums import ActorType, DecisionType
from finguard.policy.schema import PolicyConfig


class RuleResult(NamedTuple):
    matched: bool
    decision: DecisionType  # ALLOW, BLOCK, or REQUIRE_APPROVAL
    reason: str
    rule_name: str


def evaluate_max_amount_rule(tx: Transaction, actor: Actor, policy: PolicyConfig) -> RuleResult:
    """Evaluate absolute max transaction amount rule."""
    rule_name = "MaxAmountRule"

    # Agent specific limit check
    if actor.actor_type == ActorType.AGENT and policy.agent and policy.agent.max_amount:
        if tx.amount > policy.agent.max_amount:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction amount ({tx.currency.value} {tx.amount:,.2f}) exceeds agent limit ({policy.agent.currency.value} {policy.agent.max_amount:,.2f})",
                rule_name=rule_name
            )

    # General max amount check
    if policy.max_amount and policy.max_amount.amount:
        if tx.amount > policy.max_amount.amount:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction amount ({tx.currency.value} {tx.amount:,.2f}) exceeds global policy limit ({policy.max_amount.currency.value} {policy.max_amount.amount:,.2f})",
                rule_name=rule_name
            )

    return RuleResult(matched=False, decision=DecisionType.ALLOW, reason="", rule_name=rule_name)


def evaluate_destination_rule(tx: Transaction, actor: Actor, policy: PolicyConfig) -> RuleResult:
    """Evaluate destination allowlist rule."""
    rule_name = "DestinationAllowlistRule"

    # Agent specific allowlist
    if actor.actor_type == ActorType.AGENT and policy.agent and policy.agent.allowed_destinations:
        if tx.to_account not in policy.agent.allowed_destinations and "*" not in policy.agent.allowed_destinations:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Destination '{tx.to_account}' is not in agent policy allowlist ({', '.join(policy.agent.allowed_destinations)})",
                rule_name=rule_name
            )

    # Global policy allowlist
    if policy.allowed_destinations:
        if tx.to_account not in policy.allowed_destinations and "*" not in policy.allowed_destinations:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Destination '{tx.to_account}' is not in policy allowlist ({', '.join(policy.allowed_destinations)})",
                rule_name=rule_name
            )

    return RuleResult(matched=False, decision=DecisionType.ALLOW, reason="", rule_name=rule_name)


def evaluate_approval_threshold_rule(tx: Transaction, policy: PolicyConfig) -> RuleResult:
    """Evaluate whether transaction amount triggers approval requirement."""
    rule_name = "ApprovalThresholdRule"

    if policy.approval and policy.approval.required_above:
        if tx.amount > policy.approval.required_above:
            return RuleResult(
                matched=True,
                decision=DecisionType.REQUIRE_APPROVAL,
                reason=f"Transaction amount ({tx.currency.value} {tx.amount:,.2f}) exceeds threshold ({policy.approval.currency.value} {policy.approval.required_above:,.2f}) requiring maker-checker approval",
                rule_name=rule_name
            )

    return RuleResult(matched=False, decision=DecisionType.ALLOW, reason="", rule_name=rule_name)
