"""Deterministic Policy Engine for FIN//GUARD.

SECURITY PROPERTY:
- Evaluates canonical transactions against declared policy rules and actor identity capabilities.
- Produces explainable decision outcomes with explicit matched rule names and trace explanations.
- INVARIANT: Agent-initiated transactions carry a hardcoded floor of requiring at least 1 human approval
  regardless of policy configuration. An autonomous AI agent can NEVER self-authorize execution.
"""

from typing import Optional
import os
from pydantic import BaseModel, Field

from finguard.core.enums import DecisionType, ActorType
from finguard.core.transaction import Transaction
from finguard.identity.registry import ActorConfig
from finguard.policy.schema import PolicyConfig
from finguard.policy.rules import (
    evaluate_max_amount_rule,
    evaluate_destination_rule,
    evaluate_approval_threshold_rule,
)


class PolicyDecision(BaseModel):
    """Detailed result of policy evaluation."""

    allowed: bool
    decision_type: DecisionType
    reasons: list[str] = Field(default_factory=list)
    matched_rules: list[str] = Field(default_factory=list)
    policy_id: str
    policy_version: int = 1
    required_approvals: int = 0
    explanation: str = ""


class PolicyEngine:
    """Evaluates transaction security policies deterministically."""

    def __init__(self, policy: Optional[PolicyConfig] = None):
        if policy is None:
            policy_path = os.environ.get("FINGUARD_POLICY_PATH")
            if policy_path:
                from finguard.policy.parser import load_policy_from_yaml
                self.policy = load_policy_from_yaml(policy_path)
                return
            # Default fallback policy
            self.policy = PolicyConfig(
                policy_id="default-policy-v1",
                version=1,
                description="Default FIN//GUARD system policy",
                max_amount={"amount": 50000.0},
                allowed_destinations=["vendor-a", "vendor-b", "treasury-out", "payroll"],
                approval={"required_above": 20000.0, "required_approvals": 1},
                agent={"max_amount": 10000.0, "allowed_destinations": ["vendor-a", "vendor-b"]}
            )
        else:
            self.policy = policy

    def evaluate(self, transaction: Transaction, actor: ActorConfig, risk_result: Optional[dict] = None) -> PolicyDecision:
        """Evaluate a transaction against the policy.

        Returns:
            PolicyDecision with deterministic reasons and decision.
        """
        reasons: list[str] = []
        matched_rules: list[str] = []
        final_decision = DecisionType.ALLOW
        required_approvals = 0

        # Check actor authority limit directly from signed identity registry
        if transaction.amount > actor.authority_limit:
            final_decision = DecisionType.BLOCK
            matched_rules.append("IdentityAuthorityLimitRule")
            reasons.append(
                f"Transaction amount ({transaction.currency.value} {transaction.amount:,.2f}) "
                f"exceeds actor '{actor.actor_id}' authority limit ({transaction.currency.value} {actor.authority_limit:,.2f})"
            )

        # Check actor allowed destinations from signed registry
        if actor.allowed_destinations and "*" not in actor.allowed_destinations:
            if transaction.to_account not in actor.allowed_destinations:
                final_decision = DecisionType.BLOCK
                matched_rules.append("IdentityDestinationRule")
                reasons.append(
                    f"Destination '{transaction.to_account}' is not in actor '{actor.actor_id}' "
                    f"allowed destinations ({', '.join(actor.allowed_destinations)})"
                )

        # 1. Max Amount Check (Policy level)
        res_amount = evaluate_max_amount_rule(transaction, actor, self.policy)
        if res_amount.matched:
            matched_rules.append(res_amount.rule_name)
            if res_amount.decision == DecisionType.BLOCK:
                final_decision = DecisionType.BLOCK
                reasons.append(res_amount.reason)

        # 2. Destination Allowlist Check (Policy level)
        res_dest = evaluate_destination_rule(transaction, actor, self.policy)
        if res_dest.matched:
            matched_rules.append(res_dest.rule_name)
            if res_dest.decision == DecisionType.BLOCK:
                final_decision = DecisionType.BLOCK
                reasons.append(res_dest.reason)

        # If BLOCKED, return immediately (fail closed)
        if final_decision == DecisionType.BLOCK:
            explanation = "POLICY EVALUATION FAILED: " + "; ".join(reasons)
            return PolicyDecision(
                allowed=False,
                decision_type=DecisionType.BLOCK,
                reasons=reasons,
                matched_rules=matched_rules,
                policy_id=self.policy.policy_id,
                policy_version=self.policy.version,
                required_approvals=0,
                explanation=explanation
            )

        # 3. Approval Threshold Check
        res_appr = evaluate_approval_threshold_rule(transaction, self.policy)
        if res_appr.matched:
            matched_rules.append(res_appr.rule_name)
            if res_appr.decision == DecisionType.REQUIRE_APPROVAL:
                final_decision = DecisionType.REQUIRE_APPROVAL
                reasons.append(res_appr.reason)
                required_approvals = self.policy.approval.required_approvals if self.policy.approval else 1

        # LOAD-BEARING INVARIANT: Agent transactions ALWAYS require >= 1 human approval
        if actor.actor_type == ActorType.AGENT:
            required_approvals = max(1, required_approvals)
            if final_decision != DecisionType.REQUIRE_APPROVAL:
                final_decision = DecisionType.REQUIRE_APPROVAL
                matched_rules.append("AgentApprovalFloorInvariant")
                reasons.append("Agent-initiated transactions require mandatory human operator approval")

        if final_decision == DecisionType.REQUIRE_APPROVAL:
            explanation = "POLICY EVALUATION REQUIRES APPROVAL: " + "; ".join(reasons)
            return PolicyDecision(
                allowed=False,
                decision_type=DecisionType.REQUIRE_APPROVAL,
                reasons=reasons,
                matched_rules=matched_rules,
                policy_id=self.policy.policy_id,
                policy_version=self.policy.version,
                required_approvals=required_approvals,
                explanation=explanation
            )

        # All checks passed
        explanation = "POLICY EVALUATION PASSED: All policy and identity rules satisfied"
        return PolicyDecision(
            allowed=True,
            decision_type=DecisionType.ALLOW,
            reasons=["All policy rules passed"],
            matched_rules=matched_rules,
            policy_id=self.policy.policy_id,
            policy_version=self.policy.version,
            required_approvals=0,
            explanation=explanation
        )
