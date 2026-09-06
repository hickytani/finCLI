"""CLI commands for signed attestation report generation and verification."""

import json
from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel

from finguard.audit.ledger import AuditLedger
from finguard.core.config import get_config

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
        trusted_key_path = get_config().data_dir / "attestor.pub"
        trusted_key = trusted_key_path.read_text(encoding="utf-8").strip() if trusted_key_path.exists() else None
        valid_sig = AuditLedger.verify_attestation(report, trusted_pubkey_hex=trusted_key)

        if not valid_sig:
            console.print(f"[bold red]✗ ATTESTATION VERIFICATION FAILED:[/bold red] Signature is INVALID or report tampered.")
            raise typer.Exit(code=1)

        # Re-verify ledger live root hash against report root hash
        ledger = AuditLedger()
        is_valid, failing_id, reason = ledger.verify_integrity()
        live_entries = ledger._get_session()[0]
        try:
            from finguard.audit.ledger import AuditRepository
            live_records = AuditRepository(live_entries).get_all_ordered()
            live_root = live_records[-1].entry_hash if live_records else ledger.GENESIS_HASH
            live_count = len(live_records)
        finally:
            live_entries.close()
        report_matches_live = (
            live_root == report.get("chain_root_hash")
            and live_count == report.get("entry_count")
            and is_valid
        )

        console.print(Panel(
            f"Attestation File:    [cyan]{path.name}[/cyan]\n"
            f"Signature Status:    [bold green]VALID (Ed25519 Verified)[/bold green]\n"
            f"Ledger Root Hash:    [dim]{report.get('chain_root_hash')}[/dim]\n"
            f"Entries Count:       [white]{report.get('entry_count')}[/white]\n"
            f"Live Ledger Check:   [{'green' if report_matches_live else 'red'}]{'PASS' if report_matches_live else 'FAIL'}[/{'green' if report_matches_live else 'red'}]\n"
            f"Invariants Checked:  [white]{', '.join(report.get('invariants_checked', []))}[/white]",
            title="Attestation Report Verification",
            border_style="green" if (valid_sig and report_matches_live) else "red"
        ))
        if not report_matches_live:
            raise typer.Exit(code=1)

    except Exception as e:
        console.print(f"[bold red]Verification Error:[/bold red] {e}")
        raise typer.Exit(code=1)
