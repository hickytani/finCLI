"""CLI commands for deep forensic transaction investigation."""

import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from finguard.approvals.service import ApprovalService
from finguard.audit.nonce_store import NonceStore
from finguard.core.transaction import Transaction
from finguard.identity.registry import IdentityRegistry
from finguard.incidents.service import IncidentService
from finguard.policy.engine import PolicyEngine
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.repositories import TransactionRepository, AuditRepository

console = Console()


def do_investigate(transaction_id: str, output_json: bool = False):
    """Forensic investigation showing complete security decision lifecycle trace."""
    session = get_session()
    try:
        tx_repo = TransactionRepository(session)
        rec = tx_repo.get(transaction_id)
        if not rec:
            console.print(f"[bold red]Error:[/bold red] Transaction '{transaction_id}' not found.")
            raise typer.Exit(code=1)

        registry = IdentityRegistry()
        actor = registry.get_actor(rec.actor_id)

        tx = Transaction(
            transaction_id=rec.transaction_id,
            actor_id=rec.actor_id,
            session_id=rec.session_id,
            from_account=rec.from_account,
            to_account=rec.to_account,
            amount=rec.amount,
            currency=rec.currency,
            nonce=rec.nonce,
            timestamp=rec.timestamp
        )

        # Risk Engine
        risk_engine = RiskEngine(session=session)
        risk_res = risk_engine.analyze(tx, actor or registry.validate_actor("operator-1"))

        # Policy Engine
        policy_engine = PolicyEngine()
        policy_res = policy_engine.evaluate(tx, actor or registry.validate_actor("operator-1"), risk_res.model_dump())

        # Approvals
        appr_service = ApprovalService(session=session)
        appr_integrity = appr_service.verify_approval_integrity(tx)

        # Nonce
        nonce_store = NonceStore(session=session)
        nonce_used = nonce_store.has_used(rec.nonce)

        # Incidents
        inc_service = IncidentService(session=session)
        incidents = [inc.incident_id for inc in inc_service.list_incidents() if inc.transaction_id == transaction_id]

        # Audit
        audit_repo = AuditRepository(session)
        audit_entries = [e for e in audit_repo.get_all_ordered() if e.transaction_id == transaction_id]

        data = {
            "transaction_id": rec.transaction_id,
            "actor_id": rec.actor_id,
            "actor_type": actor.actor_type.value if actor else "unknown",
            "authority_limit": actor.authority_limit if actor else None,
            "amount": rec.amount,
            "currency": rec.currency,
            "nonce": rec.nonce,
            "nonce_registered": nonce_used,
            "canonical_hash": rec.canonical_hash,
            "state": rec.state,
            "policy_decision": policy_res.decision_type.value,
            "matched_rules": policy_res.matched_rules,
            "policy_explanation": policy_res.explanation,
            "risk_score": risk_res.risk_score,
            "risk_level": risk_res.risk_level.value,
            "risk_signals": risk_res.signals,
            "approval_integrity_valid": appr_integrity,
            "signature_present": bool(rec.signature),
            "incidents": incidents,
            "audit_entry_count": len(audit_entries)
        }

        if output_json:
            console.print(json.dumps(data, indent=2))
            return

        console.print(Panel(
            f"Transaction ID:    [bold cyan]{rec.transaction_id}[/bold cyan]\n"
            f"Actor:             [white]{rec.actor_id}[/white] (Type: [cyan]{data['actor_type']}[/cyan])\n"
            f"Transfer:          [white]{rec.from_account}[/white] ➔ [white]{rec.to_account}[/white]\n"
            f"Amount & Currency: [bold yellow]{rec.currency} {rec.amount:,.2f}[/bold yellow]\n"
            f"State:             [bold]{rec.state.upper()}[/bold]\n"
            f"Canonical Hash:    [dim]{rec.canonical_hash}[/dim]\n"
            f"Nonce Store:       {'Registered ✓' if nonce_used else 'Unregistered ✗'}\n"
            f"Policy Trace:      {policy_res.explanation}\n"
            f"Risk Evaluation:   Score {risk_res.risk_score}/100 ({risk_res.risk_level.value.upper()}) | Signals: {', '.join(risk_res.signals) or 'None'}\n"
            f"Approval Binding:  {'Valid ✓' if appr_integrity else 'Missing / Invalid Hash Mismatch ✗'}\n"
            f"Signature:         {'Present ✓' if rec.signature else 'Absent ✗'}\n"
            f"Incidents Fired:   {', '.join(incidents) if incidents else 'None'}\n"
            f"Audit Trail:       {len(audit_entries)} recorded ledger entries",
            title=f"Forensic Investigation: {transaction_id}",
            border_style="cyan"
        ))

    finally:
        session.close()
