"""Compatibility and Agent MVP CLI commands for FIN//GUARD (M6).

Exposes `finguard agent run --request "..."` demonstrating the complete
deterministic financial-agent pipeline from natural language to decision boundary.
"""

from __future__ import annotations

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from finguard.agent.loop import AgentOrchestratorLoop
from finguard.agent_sdk import FinGuardAgentClient

console = Console()
agent_app = typer.Typer(name="agent", help="Bounded financial agent commands")


def do_agent_tx_create(
    from_account: str,
    to_account: str,
    amount: str,
    currency: str = "INR",
    actor_id: str = "treasury-agent",
    session_id: str | None = None,
):
    """Legacy helper for programmatic agent transaction proposals."""
    client = FinGuardAgentClient(actor_id=actor_id, session_id=session_id)
    result = client.create_transaction(
        amount=amount,
        currency=currency,
        destination=to_account,
        purpose="Agent request",
        from_account=from_account,
    )
    console.print(
        Panel(
            f"Transaction ID: [bold cyan]{result.transaction.transaction_id}[/bold cyan]\n"
            f"Decision: [bold]{result.decision.value.upper()}[/bold]\n"
            f"Receipt: [dim]{result.receipt.receipt_id}[/dim]\n"
            f"Approvals: {result.receipt.approval_state}",
            title="Bounded Agent Request",
            border_style="cyan",
        )
    )
    return result


@agent_app.command("run")
def do_agent_run(
    request: str = typer.Option(..., "--request", "-r", help="Natural language request for the financial agent"),
    actor_id: str = typer.Option("agent_mcp_default", "--actor-id", "-a", help="Actor identity"),
    cancel: bool = typer.Option(False, "--cancel", help="Simulate cancellation before execution"),
):
    """Run an agentic financial workflow through the deterministic FIN//GUARD security boundary."""
    console.print(Panel(f"[bold white]{request}[/bold white]", title="REQUEST", border_style="cyan"))

    loop = AgentOrchestratorLoop(actor_id=actor_id)
    result = loop.run(request_text=request, cancellation_requested=cancel)

    # Step-by-step trace output
    table = Table(title="AGENT EXECUTION TRACE", border_style="blue")
    table.add_column("Step", style="bold yellow", width=6)
    table.add_column("Type", style="bold green", width=26)
    table.add_column("Description", style="white")

    for step in result.steps:
        table.add_row(str(step.step_number), step.step_type, step.description)

    console.print(table)

    # Final Decision & Security Boundary Box
    status_color = "green" if result.final_state == "COMPLETED" else "yellow" if result.final_state == "APPROVAL_REQUIRED" else "red"

    statement = (
        f"Final State: [bold {status_color}]{result.final_state}[/bold {status_color}]\n"
        f"Decision: [bold]{result.final_decision}[/bold]\n"
        f"Receipt ID: [dim]{result.receipt_id or 'N/A'}[/dim]\n"
        f"Tx Hash: [dim]{result.tx_hash or 'N/A'}[/dim]\n\n"
        f"[bold red]SECURITY BOUNDARY ENFORCEMENT:[/bold red]\n"
        f"• Autonomous agent CANNOT approve transactions.\n"
        f"• Autonomous agent CANNOT sign transactions.\n"
        f"• Autonomous agent CANNOT execute transactions.\n"
        f"• Autonomous agent CANNOT grant capabilities or modify policy."
    )

    console.print(Panel(statement, title="SECURITY BOUNDARY RESULT", border_style=status_color))
    return result
