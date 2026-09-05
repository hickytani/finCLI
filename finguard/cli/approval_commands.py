"""CLI commands for approval workflows."""

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from finguard.approvals.service import ApprovalService
from finguard.identity.registry import IdentityRegistry
from finguard.storage.database import get_session
from finguard.storage.repositories import ApprovalRepository

console = Console()


def do_approval_list():
    """List pending transaction approval requests."""
    session = get_session()
    try:
        appr_repo = ApprovalRepository(session)
        pending = appr_repo.list_pending()

        if not pending:
            console.print("[green]No pending approval requests.[/green]")
            return

        table = Table(title="Pending Transaction Approval Requests", border_style="cyan")
        table.add_column("Request ID", style="bold white")
        table.add_column("TX ID", style="cyan")
        table.add_column("Requester", style="white")
        table.add_column("Approvals Count", style="yellow")
        table.add_column("Created At", style="magenta")

        for r in pending:
            table.add_row(
                r.request_id,
                r.transaction_id,
                r.requester_id,
                f"{r.current_approvals} / {r.required_approvals}",
                r.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
            )

        console.print(table)
    finally:
        session.close()


def do_approval_approve(transaction_id: str, approver_id: str | None = None, key_id: str | None = None):
    """Approve a pending transaction with cryptographic signature binding."""
    approver_id = approver_id or "approver-1"
    registry = IdentityRegistry()
    approver = registry.get_actor(approver_id)

    if not approver:
        console.print(f"[bold red]Error:[/bold red] Approver '{approver_id}' not found in identity registry.")
        raise typer.Exit(code=1)

    key_id = key_id or "approver-key"
    password = Prompt.ask(f"Enter passphrase for approver key '{key_id}'", password=True)

    try:
        service = ApprovalService()
        record = service.approve_transaction(
            transaction_id=transaction_id,
            approver=approver,
            key_id=key_id,
            password=password
        )

        console.print(f"[bold green]✓ Transaction '{transaction_id}' APPROVED successfully![/bold green]")
        console.print(f"Approval ID:        [cyan]{record.approval_id}[/cyan]")
        console.print(f"Approver:           [white]{record.approver_id}[/white]")
        console.print(f"Bound TX Hash:      [dim]{record.transaction_hash}[/dim]")
        console.print(f"Approver Signature: [dim]{record.approver_signature}[/dim]")

    except Exception as e:
        console.print(f"[bold red]Approval Failed:[/bold red] {e}")
        raise typer.Exit(code=1)
