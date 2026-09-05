"""CLI commands for identity and authority management."""

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.table import Table

from finguard.core.enums import ActorType
from finguard.identity.registry import IdentityRegistry, ActorConfig

console = Console()


def do_identity_list():
    """List all registered identities and authority limits."""
    registry = IdentityRegistry()
    actors = registry.list_actors()

    if not actors:
        console.print("[yellow]No registered identities found.[/yellow]")
        return

    table = Table(title="FIN//GUARD Identity Registry", border_style="cyan")
    table.add_column("Actor ID", style="bold white")
    table.add_column("Type", style="cyan")
    table.add_column("Display Name", style="white")
    table.add_column("Authority Limit", style="yellow")
    table.add_column("Allowed Destinations", style="green")
    table.add_column("Session Req", style="magenta")

    for a in actors:
        dest_str = ", ".join(a.allowed_destinations) if a.allowed_destinations else "None"
        table.add_row(
            a.actor_id,
            a.actor_type.value,
            a.display_name,
            f"INR {a.authority_limit:,.2f}",
            dest_str,
            "Yes" if a.session_binding_required else "No"
        )

    console.print(table)


def do_identity_show(actor_id: str):
    """Show details of a specific identity."""
    registry = IdentityRegistry()
    actor = registry.get_actor(actor_id)
    if not actor:
        console.print(f"[bold red]Error:[/bold red] Actor '{actor_id}' not found in registry.")
        raise typer.Exit(code=1)

    table = Table(title=f"Identity details: {actor_id}", border_style="cyan", show_header=False)
    table.add_column("Field", style="bold white")
    table.add_column("Value")

    for k, v in actor.model_dump().items():
        table.add_row(k, str(v))

    console.print(table)


def do_identity_register(
    actor_id: str,
    actor_type: str,
    display_name: str,
    limit: float,
    destinations: str,
    root_key: str
):
    """Register a new actor in identity registry (requires root key)."""
    registry = IdentityRegistry()
    root_key_path = Path(root_key)

    dest_list = [d.strip() for d in destinations.split(",") if d.strip()]

    actor_config = ActorConfig(
        actor_id=actor_id,
        actor_type=ActorType(actor_type.lower()),
        display_name=display_name,
        authority_limit=limit,
        allowed_destinations=dest_list,
        active=True,
        session_binding_required=(actor_type.lower() == "agent")
    )

    registry.register_actor(actor_config, root_key_path)
    console.print(f"[bold green]✓ Actor '{actor_id}' registered successfully and identities.yaml re-signed.[/bold green]")
