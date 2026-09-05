"""Compatibility CLI facade for bounded agent requests.

It has no signing, approval, policy, or identity mutation operations. The
central decision engine remains the sole authorization boundary.
"""
from rich.console import Console
from rich.panel import Panel

from finguard.agent_sdk import FinGuardAgentClient

console = Console()


def do_agent_tx_create(
    from_account: str, to_account: str, amount: float, currency: str = "INR",
    actor_id: str = "treasury-agent", session_id: str | None = None,
):
    client = FinGuardAgentClient(actor_id=actor_id, session_id=session_id)
    result = client.create_transaction(
        amount=amount, currency=currency, destination=to_account,
        purpose="Agent request", from_account=from_account,
    )
    console.print(Panel(
        f"Transaction ID: [bold cyan]{result.transaction.transaction_id}[/bold cyan]\n"
        f"Decision: [bold]{result.decision.value.upper()}[/bold]\n"
        f"Receipt: [dim]{result.receipt.receipt_id}[/dim]\n"
        f"Approvals: {result.receipt.approval_state}",
        title="Bounded Agent Request", border_style="cyan",
    ))
    return result
