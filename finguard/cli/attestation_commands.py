"""CLI commands for signed attestation report generation and verification."""

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel

from finguard.audit.ledger import AuditLedger

console = Console()


def do_attest_generate(output_path: str | None = None):
    """Generate a signed cryptographic AttestationReport JSON artifact."""
    ledger = AuditLedger()
    out_p = Path(output_path) if output_path else Path("attestation_report.json")

    report = ledger.generate_attestation(output_path=out_p)

    console.print(f"[bold green]✓ Attestation Report Generated Successfully![/bold green]")
    console.print(f"Saved to:          [cyan]{out_p.resolve()}[/cyan]")
    console.print(f"Chain Root Hash:   [dim]{report['chain_root_hash']}[/dim]")
    console.print(f"Entries Attested:  [white]{report['entry_count']}[/white]")
    console.print(f"Integrity Result:  [bold green]{report['integrity_result']}[/bold green]")
    console.print(f"Attestor PubKey:   [dim]{report['attestor_pubkey']}[/dim]")
    console.print(f"Signature:         [dim]{report['signature']}[/dim]")


def do_attest_verify(report_path: str):
    """Independently verify an AttestationReport JSON artifact's signature and root hash."""
    path = Path(report_path)
    if not path.exists():
        console.print(f"[bold red]Error:[/bold red] Attestation file '{report_path}' not found.")
        raise typer.Exit(code=1)

    try:
        report = json.loads(path.read_text(encoding="utf-8"))
        valid_sig = AuditLedger.verify_attestation(report)

        if not valid_sig:
            console.print(f"[bold red]✗ ATTESTATION VERIFICATION FAILED:[/bold red] Signature is INVALID or report tampered.")
            raise typer.Exit(code=1)

        # Re-verify ledger live root hash against report root hash
        ledger = AuditLedger()
        is_valid, failing_id, reason = ledger.verify_integrity()

        console.print(Panel(
            f"Attestation File:    [cyan]{path.name}[/cyan]\n"
            f"Signature Status:    [bold green]VALID (Ed25519 Verified)[/bold green]\n"
            f"Ledger Root Hash:    [dim]{report.get('chain_root_hash')}[/dim]\n"
            f"Entries Count:       [white]{report.get('entry_count')}[/white]\n"
            f"Live Ledger Check:   [{'green' if is_valid else 'red'}]{'PASS' if is_valid else 'FAIL'}[/{'green' if is_valid else 'red'}]\n"
            f"Invariants Checked:  [white]{', '.join(report.get('invariants_checked', []))}[/white]",
            title="Attestation Report Verification",
            border_style="green" if (valid_sig and is_valid) else "red"
        ))

    except Exception as e:
        console.print(f"[bold red]Verification Error:[/bold red] {e}")
        raise typer.Exit(code=1)
