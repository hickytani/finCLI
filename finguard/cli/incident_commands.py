"""CLI commands for security incident management."""

import json
import typer
from rich.console import Console
from rich.table import Table

from finguard.incidents.service import IncidentService

console = Console()


def do_incident_list():
    """List security incidents."""
    service = IncidentService()
    incidents = service.list_incidents()

    if not incidents:
        console.print("[green]No security incidents recorded.[/green]")
        return

    table = Table(title="FIN//GUARD Security Incidents", border_style="cyan")
    table.add_column("Incident ID", style="bold white")
    table.add_column("Severity", style="bold red")
    table.add_column("TX ID", style="cyan")
    table.add_column("Actor", style="white")
    table.add_column("Decision", style="yellow")
    table.add_column("Created At", style="dim")

    for inc in incidents:
        table.add_row(
            inc.incident_id,
            inc.severity.upper(),
            inc.transaction_id or "N/A",
            inc.actor_id or "N/A",
            inc.decision or "BLOCK",
            inc.created_at.strftime("%Y-%m-%d %H:%M:%S UTC")
        )

    console.print(table)


def do_incident_show(incident_id: str, output_json: bool = False):
    """Show details of a security incident."""
    service = IncidentService()
    inc = service.get_incident(incident_id)

    if not inc:
        console.print(f"[bold red]Error:[/bold red] Incident '{incident_id}' not found.")
        raise typer.Exit(code=1)

    data = {
        "incident_id": inc.incident_id,
        "severity": inc.severity,
        "transaction_id": inc.transaction_id,
        "actor_id": inc.actor_id,
        "signals": json.loads(inc.signals) if inc.signals else [],
        "decision": inc.decision,
        "description": inc.description,
        "created_at": inc.created_at.isoformat(),
        "state": inc.state
    }

    if output_json:
        console.print(json.dumps(data, indent=2))
        return

    table = Table(title=f"Security Incident Details: {incident_id}", border_style="cyan", show_header=False)
    table.add_column("Field", style="bold white")
    table.add_column("Value")

    for k, v in data.items():
        table.add_row(k, str(v))

    console.print(table)
