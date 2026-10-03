"""Individual policy rule implementations using exact minor units comparisons."""

from typing import NamedTuple

from finguard.core.enums import ActorType, DecisionType
from finguard.core.transaction import Transaction
from finguard.identity.registry import ActorConfig as Actor
from finguard.money import Money
from finguard.policy.schema import PolicyConfig


class RuleResult(NamedTuple):
    matched: bool
    decision: DecisionType  # ALLOW, BLOCK, or REQUIRE_APPROVAL
    reason: str
    rule_name: str


def _to_minor(val: int | str, currency: str) -> int:
    return Money.from_decimal(val, currency).minor_units


def evaluate_max_amount_rule(tx: Transaction, actor: Actor, policy: PolicyConfig) -> RuleResult:
    """Evaluate absolute max transaction amount rule."""
    rule_name = "MaxAmountRule"

    # Agent specific limit check
    if actor.actor_type == ActorType.AGENT and policy.agent and policy.agent.max_amount:
        if tx.currency != policy.agent.currency:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction currency {tx.currency.value} does not match agent policy currency {policy.agent.currency.value}",
                rule_name=rule_name,
            )
        agent_max_minor = _to_minor(policy.agent.max_amount, policy.agent.currency.value)
        if tx.amount_minor > agent_max_minor:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction amount ({tx.currency.value} {tx.money.to_decimal_string()}) exceeds agent limit ({policy.agent.currency.value} {policy.agent.max_amount})",
                rule_name=rule_name
            )

    # General max amount check
    if policy.max_amount and policy.max_amount.amount:
        if tx.currency != policy.max_amount.currency:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction currency {tx.currency.value} does not match global policy currency {policy.max_amount.currency.value}",
                rule_name=rule_name,
            )
        policy_max_minor = _to_minor(policy.max_amount.amount, policy.max_amount.currency.value)
        if tx.amount_minor > policy_max_minor:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction amount ({tx.currency.value} {tx.money.to_decimal_string()}) exceeds global policy limit ({policy.max_amount.currency.value} {policy.max_amount.amount})",
                rule_name=rule_name
            )

    return RuleResult(matched=False, decision=DecisionType.ALLOW, reason="", rule_name=rule_name)


def evaluate_destination_rule(tx: Transaction, actor: Actor, policy: PolicyConfig) -> RuleResult:
    """Evaluate destination allowlist rule."""
    rule_name = "DestinationAllowlistRule"

    # Agent specific allowlist
    if (
        actor.actor_type == ActorType.AGENT
        and policy.agent
        and policy.agent.allowed_destinations
        and tx.to_account not in policy.agent.allowed_destinations
        and "*" not in policy.agent.allowed_destinations
    ):
        return RuleResult(
            matched=True,
            decision=DecisionType.BLOCK,
            reason=f"Destination '{tx.to_account}' is not in agent policy allowlist ({', '.join(policy.agent.allowed_destinations)})",
            rule_name=rule_name,
        )

    # Global policy allowlist
    if (
        policy.allowed_destinations
        and tx.to_account not in policy.allowed_destinations
        and "*" not in policy.allowed_destinations
    ):
        return RuleResult(
            matched=True,
            decision=DecisionType.BLOCK,
            reason=f"Destination '{tx.to_account}' is not in policy allowlist ({', '.join(policy.allowed_destinations)})",
            rule_name=rule_name,
        )

    return RuleResult(matched=False, decision=DecisionType.ALLOW, reason="", rule_name=rule_name)


def evaluate_approval_threshold_rule(tx: Transaction, policy: PolicyConfig) -> RuleResult:
    """Evaluate whether transaction amount triggers approval requirement."""
    rule_name = "ApprovalThresholdRule"

    if policy.approval and policy.approval.required_above is not None:
        if tx.currency != policy.approval.currency:
            return RuleResult(
                matched=True,
                decision=DecisionType.BLOCK,
                reason=f"Transaction currency {tx.currency.value} does not match approval threshold currency {policy.approval.currency.value}",
                rule_name=rule_name,
            )
        thresh_minor = _to_minor(policy.approval.required_above, policy.approval.currency.value)
        if tx.amount_minor > thresh_minor:
            return RuleResult(
                matched=True,
                decision=DecisionType.REQUIRE_APPROVAL,
                reason=f"Transaction amount ({tx.currency.value} {tx.money.to_decimal_string()}) exceeds threshold ({policy.approval.currency.value} {policy.approval.required_above}) requiring maker-checker approval",
                rule_name=rule_name
            )

    return RuleResult(matched=False, decision=DecisionType.ALLOW, reason="", rule_name=rule_name)
