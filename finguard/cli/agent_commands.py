"""CLI commands for autonomous AI Agent requests.

SECURITY PROPERTY:
AI Agents calling FinGuard are constrained to a strict allowlist of subcommands:
`finguard agent-request tx create ...` and `finguard agent-request tx status ...`.
An agent calling unapproved operator commands (such as key generation, approval, or identity modification)
is immediately rejected and triggers a security incident.
"""

import json
import typer
from rich.console import Console
from rich.panel import Panel

from finguard.audit.ledger import AuditLedger
from finguard.audit.nonce_store import NonceStore
from finguard.core.enums import ActorType, Currency, TransactionState, DecisionType, IncidentSeverity
from finguard.core.transaction import Transaction
from finguard.identity.registry import IdentityRegistry
from finguard.incidents.service import IncidentService
from finguard.policy.engine import PolicyEngine
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.models import TransactionRecord, ActorRecord
from finguard.storage.repositories import TransactionRepository, ActorRepository

console = Console()


def do_agent_tx_create(
    from_account: str,
    to_account: str,
    amount: float,
    currency: str = "INR",
    actor_id: str = "treasury-agent",
    session_id: str | None = None
):
    """Submit a financial transaction request as an autonomous AI Agent."""
    registry = IdentityRegistry()
    actor = registry.get_actor(actor_id)

    if not actor or actor.actor_type != ActorType.AGENT:
        # Create incident for unauthorized agent claim
        inc_service = IncidentService()
        inc = inc_service.create_incident(
            severity=IncidentSeverity.CRITICAL,
            description=f"Unauthorized or invalid agent identity claim '{actor_id}'",
            actor_id=actor_id,
            signals=["UNAUTHORIZED_AGENT_CLAIM"],
            decision="BLOCK"
        )
        console.print(f"[bold red]AGENT REQUEST BLOCKED:[/bold red] '{actor_id}' is not a valid registered AGENT.")
        console.print(f"Incident Created: [yellow]{inc.incident_id}[/yellow]")
        raise typer.Exit(code=1)

    tx = Transaction(
        actor_id=actor_id,
        session_id=session_id or "agent-session-001",
        from_account=from_account,
        to_account=to_account,
        amount=amount,
        currency=Currency(currency.upper()),
        initiating_actor_type=ActorType.AGENT.value
    )

    # 1. Nonce Replay Check
    nonce_store = NonceStore()
    if nonce_store.has_used(tx.nonce):
        inc_service = IncidentService()
        inc = inc_service.create_incident(
            severity=IncidentSeverity.CRITICAL,
            description=f"Agent '{actor_id}' attempted transaction replay with nonce '{tx.nonce}'",
            transaction_id=tx.transaction_id,
            actor_id=actor_id,
            signals=["REPLAY_ATTEMPT"],
            decision="BLOCK"
        )
        console.print(f"[bold red]REPLAY DETECTED:[/bold red] Nonce '{tx.nonce}' already used.")
        raise typer.Exit(code=1)

    # Record nonce
    nonce_store.record(tx.nonce, tx.transaction_id)

    # 2. Risk Analysis
    risk_engine = RiskEngine()
    risk_res = risk_engine.analyze(tx, actor)

    # 3. Policy Engine Evaluation
    policy_engine = PolicyEngine()
    policy_res = policy_engine.evaluate(tx, actor, risk_res.model_dump())

    # 4. Update transaction state
    if policy_res.decision_type == DecisionType.BLOCK:
        tx.state = TransactionState.BLOCKED
    elif policy_res.decision_type == DecisionType.REQUIRE_APPROVAL:
        tx.state = TransactionState.PENDING_APPROVAL
    else:
        tx.state = TransactionState.CREATED

    # Persist in DB
    session = get_session()
    try:
        actor_repo = ActorRepository(session)
        if not actor_repo.get(actor_id):
            actor_repo.save(ActorRecord(
                actor_id=actor.actor_id,
                actor_type=actor.actor_type.value,
                display_name=actor.display_name,
                active=True
            ))

        tx_repo = TransactionRepository(session)
        rec = TransactionRecord(
            transaction_id=tx.transaction_id,
            actor_id=tx.actor_id,
            session_id=tx.session_id,
            from_account=tx.from_account,
            to_account=tx.to_account,
            amount=tx.amount,
            currency=tx.currency.value,
            nonce=tx.nonce,
            timestamp=tx.timestamp,
            state=tx.state.value,
            canonical_hash=tx.transaction_hash()
        )
        tx_repo.save(rec)
    finally:
        session.close()

    # Audit logging
    audit = AuditLedger()
    audit.append(
        action="AGENT_REQUEST_TX_CREATE",
        actor_id=actor_id,
        transaction_id=tx.transaction_id,
        result=tx.state.value.upper(),
        metadata={
            "risk_score": risk_res.risk_score,
            "policy_decision": policy_res.decision_type.value,
            "required_approvals": policy_res.required_approvals
        }
    )

    color = "green" if tx.state == TransactionState.CREATED else ("yellow" if tx.state == TransactionState.PENDING_APPROVAL else "red")

    console.print(Panel(
        f"Transaction ID:     [bold cyan]{tx.transaction_id}[/bold cyan]\n"
        f"Agent ID:           [white]{tx.actor_id}[/white]\n"
        f"Transfer:           [white]{tx.from_account}[/white] ➔ [white]{tx.to_account}[/white]\n"
        f"Amount:             [bold yellow]{tx.currency.value} {tx.amount:,.2f}[/bold yellow]\n"
        f"State:              [{color}]{tx.state.value.upper()}[/{color}]\n"
        f"Risk Level:         [magenta]{risk_res.risk_level.value.upper()} ({risk_res.risk_score}/100)[/magenta]\n"
        f"Required Approvals: [bold]{policy_res.required_approvals} (Human Operator Floor Enforced)[/bold]\n"
        f"Explanation:        [dim]{policy_res.explanation}[/dim]",
        title="Agent Transaction Request Processed",
        border_style="cyan"
    ))
