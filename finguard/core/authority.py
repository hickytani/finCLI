"""Authority evaluation engine for FIN//GUARD.

Evaluates an actor's financial authority against a target transaction
independent of authentication credentials.
"""

from pydantic import BaseModel, Field

from finguard.core.identity import Actor
from finguard.core.transaction import Transaction


class AuthorityDecision(BaseModel):
    """Result of an authority evaluation."""

    allowed: bool
    reasons: list[str] = Field(default_factory=list)
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

    if not actor.active:
        return AuthorityDecision(
            allowed=False,
            reasons=["Actor is inactive / disabled"],
            actor_id=actor.actor_id,
            transaction_id=transaction.transaction_id,
        )

    auth = actor.authority

    # 1. Action permission check
    if action and auth.allowed_actions:
        if action not in auth.allowed_actions and "*" not in auth.allowed_actions:
            reasons.append(f"Actor lacks permission for action '{action}'")

    # 2. Maximum transaction amount check
    if transaction.amount > auth.max_transaction_amount:
        reasons.append(
            f"Transaction amount ({transaction.currency.value} {transaction.amount:,.2f}) "
            f"exceeds actor maximum limit ({auth.currency.value} {auth.max_transaction_amount:,.2f})"
        )

    # 3. Allowed destinations check
    if auth.allowed_destinations:
        if transaction.to_account not in auth.allowed_destinations and "*" not in auth.allowed_destinations:
            reasons.append(
                f"Destination '{transaction.to_account}' is not in actor allowed destinations list "
                f"({', '.join(auth.allowed_destinations)})"
            )

    is_allowed = len(reasons) == 0

    return AuthorityDecision(
        allowed=is_allowed,
        reasons=reasons if not is_allowed else ["Authority checks passed"],
        actor_id=actor.actor_id,
        transaction_id=transaction.transaction_id,
    )
