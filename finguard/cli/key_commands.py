"""CLI commands for cryptographic key management."""

import typer
from rich.console import Console
from rich.table import Table
from rich.prompt import Prompt

from finguard.crypto.keystore import Keystore
from finguard.core.errors import KeystoreError

console = Console()


def do_key_list():
    """List all stored keys in the keystore."""
    keystore = Keystore()
    keys = keystore.list_keys()

    if not keys:
        console.print("[yellow]No keys found in keystore.[/yellow]")
        console.print("Generate one using: [cyan]finguard key generate[/cyan]")
        return

    table = Table(title="FIN//GUARD Stored Keys", border_style="cyan")
    table.add_column("Key ID", style="bold white")
    table.add_column("Algorithm", style="green")
    table.add_column("Fingerprint", style="magenta")
    table.add_column("Public Key", style="dim")

    for k in keys:
        pub_short = k['public_key_hex'][:20] + "..." if k['public_key_hex'] else ""
        table.add_row(k["key_id"], k["algorithm"], k["fingerprint"] or "", pub_short)

    console.print(table)


def do_key_generate(key_id: str | None = None, passphrase: str | None = None):
    """Generate a new Ed25519 keypair and save it encrypted."""
    if not key_id:
        key_id = Prompt.ask("Enter unique Key ID", default="master-key")

    if not passphrase:
        password = Prompt.ask("Enter passphrase to encrypt private key", password=True)
        confirm_pw = Prompt.ask("Confirm passphrase", password=True)
        if password != confirm_pw:
            console.print("[bold red]Error:[/bold red] Passphrases do not match.")
            raise typer.Exit(code=1)
    else:
        password = passphrase

    if not password:
        console.print("[bold red]Error:[/bold red] Passphrase cannot be empty.")
        raise typer.Exit(code=1)

    keystore = Keystore()
    try:
        pub_hex = keystore.create_keypair(key_id, password)
        console.print(f"[bold green]✓ Keypair '{key_id}' successfully created and encrypted![/bold green]")
        console.print(f"Algorithm:   [cyan]Ed25519[/cyan]")
        console.print(f"Public Key:  [dim]{pub_hex}[/dim]")
        console.print(f"Fingerprint: [magenta]{pub_hex[:16]}[/magenta]")
    except KeystoreError as e:
        console.print(f"[bold red]Keystore Error:[/bold red] {e}")
        raise typer.Exit(code=1)


def do_key_inspect(key_id: str):
    """Inspect public details of a stored key."""
    keystore = Keystore()
    try:
        pub_hex = keystore.get_public_key(key_id)
        console.print(f"[bold cyan]Key Details for '{key_id}':[/bold cyan]")
        console.print(f"Algorithm:   [cyan]Ed25519[/cyan]")
        console.print(f"Public Key:  [white]{pub_hex}[/white]")
        console.print(f"Fingerprint: [magenta]{pub_hex[:16]}[/magenta]")
    except KeystoreError as e:
        console.print(f"[bold red]Error:[/bold red] {e}")
        raise typer.Exit(code=1)
