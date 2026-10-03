"""Authority evaluation engine for FIN//GUARD.

Evaluates an actor's financial authority against a target transaction
independent of authentication credentials.
"""

from pydantic import BaseModel, Field

from finguard.core.enums import ActorType
from finguard.core.identity import Actor
from finguard.core.transaction import Transaction


class AuthorityDecision(BaseModel):
    """Result of an authority evaluation."""

    allowed: bool
    reasons: list[str] = Field(default_factory=list)
    signals: list[str] = Field(default_factory=list)
    actor_id: str
    transaction_id: str


def evaluate_authority(actor: Actor, transaction: Transaction, action: str = "tx:create") -> AuthorityDecision:
    """Evaluate whether an actor has authority to perform an action on a transaction.

    Args:
        actor: Actor identity and authority model.
        transaction: Canonical transaction model.
        action: Requested action name (e.g., 'tx:create', 'tx:sign').

    Returns:
        AuthorityDecision with allowed flag and explicit decision reasons.
    """
    reasons = []
    signals = []

    if not actor.active:
        return AuthorityDecision(
            allowed=False,
            reasons=["Actor is inactive / disabled"],
            actor_id=actor.actor_id,
            transaction_id=transaction.transaction_id,
        )

    auth = actor.authority

    # 1. Action permission check
    action_wildcard = "*" in auth.allowed_actions
    explicit_actions = [allowed for allowed in auth.allowed_actions if allowed != "*"]
    if not auth.allowed_actions:
        reasons.append("Actor has empty allowed_actions list (deny-by-default)")
    elif action and action not in explicit_actions:
        if action_wildcard and actor.actor_type != ActorType.AGENT:
            signals.append("WILDCARD_AUTHORITY_USED")
        elif action_wildcard and actor.actor_type == ActorType.AGENT:
            reasons.append("Agent wildcard action authority is forbidden")
        else:
            reasons.append(f"Actor lacks explicit permission for action '{action}'")

    source_wildcard = "*" in auth.allowed_source_accounts
    explicit_sources = [account for account in auth.allowed_source_accounts if account != "*"]
    if not auth.allowed_source_accounts:
        reasons.append("Actor has empty allowed_source_accounts list (deny-by-default)")
    elif transaction.from_account not in explicit_sources:
        if source_wildcard and actor.actor_type != ActorType.AGENT:
            signals.append("WILDCARD_AUTHORITY_USED")
        elif source_wildcard and actor.actor_type == ActorType.AGENT:
            reasons.append("Agent wildcard source authority is forbidden")
        else:
            reasons.append(f"Source '{transaction.from_account}' is not explicitly authorized")

    # 2. Maximum transaction amount check
    if transaction.currency != auth.currency:
        reasons.append("Transaction currency does not match authority currency")
    elif transaction.amount_minor > auth.max_transaction_amount_minor:
        reasons.append(
            f"Transaction amount ({transaction.currency.value} {transaction.money.to_decimal_string()}) "
            f"exceeds actor maximum limit ({auth.currency.value} {auth.max_transaction_amount:,.2f})"
        )

    # 3. Allowed destinations check (deny-by-default)
    destination_wildcard = "*" in auth.allowed_destinations
    explicit_destinations = [account for account in auth.allowed_destinations if account != "*"]
    if not auth.allowed_destinations:
        reasons.append("Actor has empty allowed_destinations list (deny-by-default)")
    elif transaction.to_account not in explicit_destinations:
        if destination_wildcard and actor.actor_type != ActorType.AGENT:
            signals.append("WILDCARD_AUTHORITY_USED")
        elif destination_wildcard and actor.actor_type == ActorType.AGENT:
            reasons.append("Agent wildcard destination authority is forbidden")
        else:
            reasons.append(f"Destination '{transaction.to_account}' is not explicitly authorized")

    is_allowed = len(reasons) == 0

    return AuthorityDecision(
        allowed=is_allowed,
        reasons=reasons if not is_allowed else ["Authority checks passed"],
        signals=sorted(set(signals)),
        actor_id=actor.actor_id,
        transaction_id=transaction.transaction_id,
    )
