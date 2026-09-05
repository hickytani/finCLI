"""CLI commands for audit ledger management and tampering detection."""

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

from finguard.audit.ledger import AuditLedger
from finguard.storage.database import get_session
from finguard.storage.repositories import AuditRepository

console = Console()


def do_audit_show(limit: int = 20):
    """Show recent entries from the tamper-evident audit ledger."""
    session = get_session()
    try:
        repo = AuditRepository(session)
        entries = repo.get_recent(limit=limit)

        if not entries:
            console.print("[yellow]Audit ledger is empty.[/yellow]")
            return

        table = Table(title="FIN//GUARD Tamper-Evident Audit Ledger", border_style="cyan")
        table.add_column("# ID", style="bold white")
        table.add_column("Timestamp", style="dim")
        table.add_column("Actor", style="cyan")
        table.add_column("Action", style="white")
        table.add_column("TX ID", style="yellow")
        table.add_column("Result", style="bold")
        table.add_column("Entry Hash", style="dim")

        for e in reversed(entries):
            res_color = "green" if e.result == "PASS" else ("red" if e.result in ("BLOCKED", "FAIL") else "yellow")
            table.add_row(
                str(e.entry_id),
                e.timestamp.strftime("%H:%M:%S UTC"),
                e.actor_id or "system",
                e.action,
                e.transaction_id or "N/A",
                f"[{res_color}]{e.result}[/{res_color}]",
                f"{e.entry_hash[:12]}..."
            )

        console.print(table)
    finally:
        session.close()


def do_audit_verify():
    """Verify hash chain integrity across all historical audit entries."""
    ledger = AuditLedger()
    is_valid, failing_id, reason = ledger.verify_integrity()

    if is_valid:
        console.print(f"[bold green]AUDIT CHAIN INTEGRITY: PASS[/bold green]")
        console.print(f"[white]{reason}[/white]")
    else:
        console.print(f"[bold red]AUDIT CHAIN BROKEN — TAMPERING DETECTED![/bold red]")
        console.print(f"Failing Entry ID: [yellow]#{failing_id}[/yellow]")
        console.print(f"Reason:           [red]{reason}[/red]")
        raise typer.Exit(code=1)


def do_audit_export(format: str = "json", output: str | None = None):
    """Export complete audit ledger for offline forensics or archival."""
    session = get_session()
    try:
        repo = AuditRepository(session)
        entries = repo.get_all_ordered()

        out_path = Path(output) if output else Path(f"finguard_audit_export.{format.lower()}")

        data = [
            {
                "entry_id": e.entry_id,
                "timestamp": e.timestamp.isoformat(),
                "actor_id": e.actor_id,
                "action": e.action,
                "transaction_id": e.transaction_id,
                "result": e.result,
                "metadata": json.loads(e.metadata_json) if e.metadata_json else None,
                "previous_hash": e.previous_hash,
                "entry_hash": e.entry_hash
            }
            for e in entries
        ]

        if format.lower() == "json":
            out_path.write_text(json.dumps(data, indent=2), encoding="utf-8")
        else:
            # CSV export
            import csv
            with open(out_path, "w", newline="", encoding="utf-8") as f:
                writer = csv.DictWriter(f, fieldnames=data[0].keys() if data else [])
                writer.writeheader()
                writer.writerows(data)

        console.print(f"[bold green]✓ Audit ledger exported successfully to '{out_path}'[/bold green]")
    finally:
        session.close()
