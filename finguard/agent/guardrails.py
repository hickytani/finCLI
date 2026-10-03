"""Deterministic proposal preflight for the untrusted agent boundary."""

from __future__ import annotations

from enum import Enum

from pydantic import BaseModel, ConfigDict

from finguard.core.enums import (
    ActorType,
    AgentAction,
    AgentCapability,
    AgentRequestOutcome,
    AgentResource,
    DecisionType,
)
from finguard.core.transaction import Transaction
from finguard.identity.registry import ActorConfig
from finguard.money import Money


class GuardrailReasonCode(str, Enum):
    """Stable reason codes emitted by agent preflight."""

    GUARDRAIL_PASSED = "GUARDRAIL_PASSED"
    CAPABILITY_MISSING = "CAPABILITY_MISSING"
    UNSUPPORTED_CAPABILITY = "UNSUPPORTED_CAPABILITY"
    ACTION_NOT_ALLOWED = "ACTION_NOT_ALLOWED"
    PRIVILEGE_ESCALATION = "PRIVILEGE_ESCALATION"
    RESOURCE_NOT_ALLOWED = "RESOURCE_NOT_ALLOWED"
    INVALID_TRANSACTION = "INVALID_TRANSACTION"
    CURRENCY_NOT_ALLOWED = "CURRENCY_NOT_ALLOWED"
    AMOUNT_LIMIT_EXCEEDED = "AMOUNT_LIMIT_EXCEEDED"
    SOURCE_NOT_ALLOWED = "SOURCE_NOT_ALLOWED"
    TARGET_NOT_ALLOWED = "TARGET_NOT_ALLOWED"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    POLICY_REQUIRES_APPROVAL = "POLICY_REQUIRES_APPROVAL"


class GuardrailResult(BaseModel):
    """Auditable result of guardrail preflight and downstream core outcome."""

    model_config = ConfigDict(frozen=True)

    status: AgentRequestOutcome
    reason_code: GuardrailReasonCode
    actor_id: str
    intent_id: str
    correlation_id: str
    capability: str
    action: str
    resource_type: str
    transaction_hash: str
    reason: str


_CAPABILITY_ACTION_RESOURCES: dict[
    tuple[AgentCapability, AgentAction], AgentResource
] = {
    (AgentCapability.TRANSACTION_PROPOSE, AgentAction.TRANSACTION_PROPOSE):
        AgentResource.TRANSACTION,
}
_PRIVILEGED_ACTIONS = {
    AgentAction.TRANSACTION_APPROVE,
    AgentAction.TRANSACTION_SIGN,
    AgentAction.TRANSACTION_EXECUTE,
}


class AgentGuardrails:
    """Check the request may reach the core; never make the core's decision."""

    @staticmethod
    def evaluate(
        *,
        actor: ActorConfig,
        intent_id: str,
        correlation_id: str,
        capability: str,
        action: str,
        resource_type: str,
        transaction: Transaction,
    ) -> GuardrailResult:
        def result(code: GuardrailReasonCode, reason: str) -> GuardrailResult:
            return GuardrailResult(
                status=AgentRequestOutcome.DENY,
                reason_code=code,
                actor_id=actor.actor_id,
                intent_id=intent_id,
                correlation_id=correlation_id,
                capability=capability,
                action=action,
                resource_type=resource_type,
                transaction_hash=transaction.transaction_hash(),
                reason=reason,
            )

        if (
            actor.actor_type != ActorType.AGENT
            or not actor.active
            or transaction.actor_id != actor.actor_id
            or transaction.initiating_actor_type != ActorType.AGENT.value
        ):
            return result(
                GuardrailReasonCode.INVALID_TRANSACTION,
                "Transaction identity is not bound to this active agent",
            )
        try:
            requested_action = AgentAction(action)
        except ValueError:
            return result(
                GuardrailReasonCode.ACTION_NOT_ALLOWED,
                "Requested action is not in the supported agent action set",
            )
        if requested_action in _PRIVILEGED_ACTIONS:
            return result(
                GuardrailReasonCode.PRIVILEGE_ESCALATION,
                "Agents cannot approve, sign, or execute transactions",
            )
        try:
            requested_capability = AgentCapability(capability)
        except ValueError:
            return result(
                GuardrailReasonCode.UNSUPPORTED_CAPABILITY,
                "Requested capability is not in the supported agent capability set",
            )
        if requested_capability not in actor.agent_capabilities:
            return result(
                GuardrailReasonCode.CAPABILITY_MISSING,
                "Capability is not granted by the signed actor identity",
            )
        bound_resource = _CAPABILITY_ACTION_RESOURCES.get(
            (requested_capability, requested_action)
        )
        if bound_resource is None:
            return result(
                GuardrailReasonCode.ACTION_NOT_ALLOWED,
                "Capability is not bound to the requested action",
            )
        if resource_type != bound_resource.value:
            return result(
                GuardrailReasonCode.RESOURCE_NOT_ALLOWED,
                "Capability and action are not bound to the requested resource",
            )

        if transaction.amount_minor <= 0:
            return result(
                GuardrailReasonCode.INVALID_TRANSACTION,
                "Transaction amount must be positive",
            )
        if transaction.currency != actor.authority_currency:
            return result(
                GuardrailReasonCode.CURRENCY_NOT_ALLOWED,
                "Transaction currency does not match the signed agent currency",
            )
        authority_limit = Money.from_decimal(
            actor.authority_limit, actor.authority_currency
        ).minor_units
        if transaction.amount_minor > authority_limit:
            return result(
                GuardrailReasonCode.AMOUNT_LIMIT_EXCEEDED,
                "Transaction exceeds the signed agent amount limit",
            )

        allowed_sources = set(actor.allowed_source_accounts)
        allowed_targets = set(actor.allowed_destinations)
        if (
            not allowed_sources
            or "*" in allowed_sources
            or transaction.from_account not in allowed_sources
        ):
            return result(
                GuardrailReasonCode.SOURCE_NOT_ALLOWED,
                "Source account is not explicitly granted to this agent",
            )
        if (
            not allowed_targets
            or "*" in allowed_targets
            or transaction.to_account not in allowed_targets
        ):
            return result(
                GuardrailReasonCode.TARGET_NOT_ALLOWED,
                "Target account is not explicitly granted to this agent",
            )

        return GuardrailResult(
            status=AgentRequestOutcome.ALLOW,
            reason_code=GuardrailReasonCode.GUARDRAIL_PASSED,
            actor_id=actor.actor_id,
            intent_id=intent_id,
            correlation_id=correlation_id,
            capability=capability,
            action=action,
            resource_type=resource_type,
            transaction_hash=transaction.transaction_hash(),
            reason="Proposal may proceed to deterministic policy evaluation",
        )

    @staticmethod
    def record_core_outcome(
        preflight: GuardrailResult,
        decision: DecisionType,
    ) -> GuardrailResult:
        """Keep preflight distinct while reflecting the authoritative core result."""
        if preflight.status == AgentRequestOutcome.DENY:
            return preflight
        if decision == DecisionType.REQUIRE_APPROVAL:
            status = AgentRequestOutcome.APPROVAL_REQUIRED
            code = GuardrailReasonCode.POLICY_REQUIRES_APPROVAL
            reason = "Existing policy core requires trusted human approval"
        elif decision == DecisionType.BLOCK:
            status = AgentRequestOutcome.DENY
            code = GuardrailReasonCode.POLICY_BLOCKED
            reason = "Existing deterministic security core blocked the proposal"
        else:
            status = AgentRequestOutcome.ALLOW
            code = GuardrailReasonCode.GUARDRAIL_PASSED
            reason = "Existing deterministic core allowed the proposal to proceed"
        return preflight.model_copy(
            update={"status": status, "reason_code": code, "reason": reason}
        )
