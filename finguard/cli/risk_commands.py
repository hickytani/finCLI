"""CLI commands for risk analysis."""

import json
import typer
from rich.console import Console
from rich.table import Table

from finguard.core.transaction import Transaction
from finguard.identity.registry import IdentityRegistry
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.repositories import TransactionRepository

console = Console()


def do_risk_analyze(transaction_id: str, output_json: bool = False):
    """Analyze risk signals for a transaction."""
    session = get_session()
    try:
        tx_repo = TransactionRepository(session)
        rec = tx_repo.get(transaction_id)
        if not rec:
            console.print(f"[bold red]Error:[/bold red] Transaction '{transaction_id}' not found.")
            raise typer.Exit(code=1)

        registry = IdentityRegistry()
        actor = registry.get_actor(rec.actor_id)
        if not actor:
            actor = registry.validate_actor("operator-1")

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

        risk_engine = RiskEngine(session=session)
        res = risk_engine.analyze(tx, actor)

        if output_json:
            console.print(json.dumps(res.model_dump(), indent=2))
            return

        table = Table(title=f"Risk Analysis: {transaction_id}", border_style="cyan", show_header=False)
        table.add_column("Field", style="bold white")
        table.add_column("Value")

        table.add_row("Transaction ID", res.transaction_id)
        table.add_row("Risk Score", f"{res.risk_score} / 100")
        table.add_row("Risk Level", res.risk_level.value.upper())
        table.add_row("Signals Fired", ", ".join(res.signals) if res.signals else "None")
        table.add_row("Explanation", res.explanation)

        console.print(table)
    finally:
        session.close()
