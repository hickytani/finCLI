"""CLI commands for forensic investigation.

Provides the `finguard investigate` subcommand group with:
    incident-trace   — full trace for an incident (TX, signals, receipt, audit)
    tx-trace         — full forensic trace for a transaction
    events           — paginated, filtered event search
    actor-profile    — security posture for an actor
    timeline         — chronological merged timeline for an incident
    transition       — advance an incident through its lifecycle
"""

import datetime
import json

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from finguard.core.errors import SecurityError
from finguard.incidents.service import IncidentService, InvalidTransitionError
from finguard.investigation.service import InvestigationService

console = Console()


# ---------------------------------------------------------------------------
# investigate incident-trace
# ---------------------------------------------------------------------------

def do_incident_trace(incident_id: str, output_json: bool = False) -> None:
    """Display the full forensic trace for a security incident."""
    svc = InvestigationService()
    try:
        trace = svc.get_incident_trace(incident_id)
    except SecurityError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output_json:
        data = {
            "incident": {
                "incident_id": trace.incident.incident_id,
                "severity": trace.incident.severity,
                "state": trace.incident.state,
                "actor_id": trace.incident.actor_id,
                "transaction_id": trace.incident.transaction_id,
                "description": trace.incident.description,
                "decision": trace.incident.decision,
                "signals": json.loads(trace.incident.signals) if trace.incident.signals else [],
                "created_at": trace.incident.created_at.isoformat(),
                "resolved_at": trace.incident.resolved_at.isoformat() if trace.incident.resolved_at else None,
                "resolved_by": trace.incident.resolved_by,
                "state_note": trace.incident.state_note,
            },
            "transaction": {
                "transaction_id": trace.transaction.transaction_id,
                "actor_id": trace.transaction.actor_id,
                "amount": trace.transaction.amount,
                "currency": trace.transaction.currency,
                "from_account": trace.transaction.from_account,
                "to_account": trace.transaction.to_account,
                "state": trace.transaction.state,
                "timestamp": trace.transaction.timestamp.isoformat(),
                "canonical_hash": trace.transaction.canonical_hash,
            } if trace.transaction else None,
            "signals": [
                {
                    "signal_id": s.signal_id,
                    "signal_type": s.signal_type,
                    "score": s.score,
                    "description": s.description,
                }
                for s in trace.signals
            ],
            "receipt": {
                "receipt_id": trace.receipt.receipt_id,
                "decision": trace.receipt.decision,
                "risk_score": trace.receipt.risk_score,
                "risk_level": trace.receipt.risk_level,
                "reasons": trace.receipt.reasons,
                "timestamp": trace.receipt.timestamp.isoformat(),
            } if trace.receipt else None,
            "audit_entries": [
                {
                    "entry_id": a.entry_id,
                    "action": a.action,
                    "actor_id": a.actor_id,
                    "result": a.result,
                    "timestamp": a.timestamp.isoformat(),
                    "metadata": a.metadata,
                }
                for a in trace.audit_entries
            ],
        }
        console.print(json.dumps(data, indent=2))
        return

    # Rich formatted output
    inc = trace.incident
    console.print(Panel(
        f"[bold white]Incident:[/bold white] {inc.incident_id}  "
        f"Severity: [bold red]{inc.severity.upper()}[/bold red]  "
        f"State: [bold cyan]{inc.state}[/bold cyan]\n"
        f"Actor: {inc.actor_id or 'N/A'}  |  Transaction: {inc.transaction_id or 'N/A'}\n"
        f"Description: {inc.description or 'N/A'}\n"
        f"Decision: {inc.decision or 'N/A'}  |  Created: {inc.created_at.strftime('%Y-%m-%d %H:%M:%S UTC')}",
        title=f"Incident Trace: {incident_id}",
        border_style="red",
    ))

    if trace.transaction:
        tx = trace.transaction
        table = Table(title="Triggering Transaction", border_style="cyan", show_header=False)
        table.add_column("Field", style="bold white")
        table.add_column("Value")
        table.add_row("Transaction ID", tx.transaction_id)
        table.add_row("Actor", tx.actor_id)
        table.add_row("Transfer", f"{tx.from_account} → {tx.to_account}")
        table.add_row("Amount", f"{tx.currency} {tx.amount}")
        table.add_row("State", tx.state.upper())
        table.add_row("Timestamp", tx.timestamp.strftime("%Y-%m-%d %H:%M:%S UTC"))
        table.add_row("Canonical Hash", tx.canonical_hash or "N/A")
        console.print(table)

    if trace.signals:
        sig_table = Table(title="Security Signals", border_style="yellow")
        sig_table.add_column("Type", style="bold yellow")
        sig_table.add_column("Score")
        sig_table.add_column("Description")
        for s in trace.signals:
            sig_table.add_row(s.signal_type, str(s.score), s.description or "")
        console.print(sig_table)
    else:
        console.print("[dim]No security signals attached to this incident's transaction.[/dim]")

    if trace.receipt:
        r = trace.receipt
        console.print(Panel(
            f"Decision: [bold]{r.decision.upper()}[/bold]  "
            f"Risk Score: {r.risk_score} ({r.risk_level})\n"
            f"Reasons: {'; '.join(r.reasons) or 'N/A'}",
            title="Decision Receipt",
            border_style="magenta",
        ))

    if trace.audit_entries:
        a_table = Table(title=f"Audit Trail ({len(trace.audit_entries)} entries)", border_style="dim")
        a_table.add_column("#", style="dim")
        a_table.add_column("Action", style="bold white")
        a_table.add_column("Actor")
        a_table.add_column("Result")
        a_table.add_column("Timestamp")
        for a in trace.audit_entries:
            a_table.add_row(
                str(a.entry_id),
                a.action,
                a.actor_id or "system",
                a.result or "",
                a.timestamp.strftime("%Y-%m-%d %H:%M:%S"),
            )
        console.print(a_table)


# ---------------------------------------------------------------------------
# investigate tx-trace
# ---------------------------------------------------------------------------

def do_tx_trace(transaction_id: str, output_json: bool = False) -> None:
    """Display full forensic trace for a transaction."""
    svc = InvestigationService()
    try:
        trace = svc.get_transaction_trace(transaction_id)
    except SecurityError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output_json:
        data = {
            "transaction": {
                "transaction_id": trace["transaction"].transaction_id,
                "actor_id": trace["transaction"].actor_id,
                "amount": trace["transaction"].amount,
                "currency": trace["transaction"].currency,
                "from_account": trace["transaction"].from_account,
                "to_account": trace["transaction"].to_account,
                "state": trace["transaction"].state,
                "timestamp": trace["transaction"].timestamp.isoformat(),
                "canonical_hash": trace["transaction"].canonical_hash,
                "nonce": trace["transaction"].nonce,
            },
            "signals": [
                {"signal_id": s.signal_id, "signal_type": s.signal_type, "score": s.score}
                for s in trace["signals"]
            ],
            "receipt": {
                "receipt_id": trace["receipt"].receipt_id,
                "decision": trace["receipt"].decision,
                "risk_score": trace["receipt"].risk_score,
                "risk_level": trace["receipt"].risk_level,
                "reasons": trace["receipt"].reasons,
            } if trace["receipt"] else None,
            "incidents": [inc.incident_id for inc in trace["incidents"]],
            "audit_entry_count": len(trace["audit_entries"]),
        }
        console.print(json.dumps(data, indent=2))
        return

    tx = trace["transaction"]
    console.print(Panel(
        f"TX: [bold cyan]{tx.transaction_id}[/bold cyan]  Actor: {tx.actor_id}\n"
        f"{tx.from_account} → {tx.to_account}  {tx.currency} {tx.amount}\n"
        f"State: [bold]{tx.state.upper()}[/bold]  Hash: [dim]{tx.canonical_hash}[/dim]\n"
        f"Signals: {len(trace['signals'])}  |  Incidents: {len(trace['incidents'])}  |  Audit: {len(trace['audit_entries'])} entries",
        title=f"Transaction Trace: {transaction_id}",
        border_style="cyan",
    ))


# ---------------------------------------------------------------------------
# investigate events
# ---------------------------------------------------------------------------

def do_event_search(
    actor: str | None = None,
    state: str | None = None,
    to_account: str | None = None,
    from_account: str | None = None,
    since: str | None = None,
    until: str | None = None,
    min_amount: float | None = None,
    max_amount: float | None = None,
    page: int = 1,
    page_size: int = 20,
    output_json: bool = False,
) -> None:
    """Search and filter security events (transactions) with pagination."""
    since_dt = _parse_dt(since, "since") if since else None
    until_dt = _parse_dt(until, "until") if until else None

    svc = InvestigationService()
    try:
        result = svc.search_events(
            actor_id=actor,
            state=state,
            to_account=to_account,
            from_account=from_account,
            since=since_dt,
            until=until_dt,
            min_amount=min_amount,
            max_amount=max_amount,
            page=page,
            page_size=page_size,
        )
    except SecurityError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output_json:
        console.print(json.dumps({
            "total": result.total,
            "page": result.page,
            "page_size": result.page_size,
            "has_next": result.has_next,
            "items": [
                {
                    "transaction_id": t.transaction_id,
                    "actor_id": t.actor_id,
                    "amount": t.amount,
                    "currency": t.currency,
                    "from_account": t.from_account,
                    "to_account": t.to_account,
                    "state": t.state,
                    "timestamp": t.timestamp.isoformat(),
                }
                for t in result.items
            ],
        }, indent=2))
        return

    console.print(
        f"[bold]Event Search[/bold]  Total: {result.total}  "
        f"Page {result.page} of {max(1, (result.total + result.page_size - 1) // result.page_size)}"
        f"{'  [dim](more available)[/dim]' if result.has_next else ''}"
    )

    if not result.items:
        console.print("[dim]No events match the search criteria.[/dim]")
        return

    table = Table(border_style="cyan")
    table.add_column("TX ID", style="bold white")
    table.add_column("Actor")
    table.add_column("From → To")
    table.add_column("Amount")
    table.add_column("State")
    table.add_column("Timestamp")

    for t in result.items:
        table.add_row(
            t.transaction_id,
            t.actor_id,
            f"{t.from_account} → {t.to_account}",
            f"{t.currency} {t.amount}",
            t.state.upper(),
            t.timestamp.strftime("%Y-%m-%d %H:%M"),
        )

    console.print(table)


# ---------------------------------------------------------------------------
# investigate actor-profile
# ---------------------------------------------------------------------------

def do_actor_profile(actor_id: str, output_json: bool = False) -> None:
    """Display security posture and risk profile for an actor."""
    svc = InvestigationService()
    try:
        profile = svc.get_actor_profile(actor_id)
    except SecurityError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output_json:
        console.print(json.dumps({
            "actor_id": profile.actor_id,
            "total_transactions_in_db": profile.total_transactions_in_db,
            "open_incidents": profile.open_incidents,
            "risk_contributors": profile.risk_contributors,
            "recent_transactions_count": len(profile.recent_transactions),
            "incidents_count": len(profile.incidents),
        }, indent=2))
        return

    console.print(Panel(
        f"Actor: [bold cyan]{profile.actor_id}[/bold cyan]\n"
        f"Total transactions in DB: {profile.total_transactions_in_db}\n"
        f"Open incidents: [bold {'red' if profile.open_incidents > 0 else 'green'}]{profile.open_incidents}[/bold {'red' if profile.open_incidents > 0 else 'green'}]\n"
        f"Risk signals: {dict(sorted(profile.risk_contributors.items(), key=lambda x: -x[1]))}",
        title=f"Security Profile: {actor_id}",
        border_style="magenta",
    ))

    if profile.incidents:
        inc_table = Table(title="Incidents", border_style="red")
        inc_table.add_column("Incident ID", style="bold white")
        inc_table.add_column("Severity")
        inc_table.add_column("State")
        inc_table.add_column("Created")
        for i in profile.incidents[:10]:
            inc_table.add_row(
                i.incident_id,
                i.severity.upper(),
                i.state,
                i.created_at.strftime("%Y-%m-%d %H:%M"),
            )
        console.print(inc_table)


# ---------------------------------------------------------------------------
# investigate timeline
# ---------------------------------------------------------------------------

def do_incident_timeline(incident_id: str, output_json: bool = False) -> None:
    """Display a deterministic chronological timeline for an incident."""
    svc = InvestigationService()
    try:
        items = svc.get_incident_timeline(incident_id)
    except SecurityError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output_json:
        console.print(json.dumps([
            {
                "timestamp": item.timestamp.isoformat(),
                "source_type": item.source_type,
                "source_id": item.source_id,
                "summary": item.summary,
                "metadata": item.metadata,
            }
            for item in items
        ], indent=2))
        return

    console.print(f"\n[bold]Investigation Timeline for {incident_id}[/bold]  ({len(items)} events)\n")

    SOURCE_COLORS = {
        "incident": "red",
        "transaction": "cyan",
        "signal": "yellow",
        "receipt": "magenta",
        "audit": "dim",
    }

    for item in items:
        color = SOURCE_COLORS.get(item.source_type, "white")
        ts = item.timestamp.strftime("%Y-%m-%d %H:%M:%S")
        console.print(
            f"  [dim]{ts}[/dim]  [{color}][{item.source_type.upper():12s}][/{color}]  {item.summary}"
        )

    console.print()


# ---------------------------------------------------------------------------
# investigate transition
# ---------------------------------------------------------------------------

def do_incident_transition(
    incident_id: str,
    new_state: str,
    actor_id: str,
    note: str | None = None,
    output_json: bool = False,
) -> None:
    """Advance an incident to a new lifecycle state."""
    svc = IncidentService()
    try:
        record = svc.transition_incident(
            incident_id=incident_id,
            new_state=new_state,
            requesting_actor_id=actor_id,
            note=note,
        )
    except InvalidTransitionError as exc:
        console.print(f"[bold red]Invalid transition:[/bold red] {exc}")
        raise typer.Exit(code=1)
    except SecurityError as exc:
        console.print(f"[bold red]Error:[/bold red] {exc}")
        raise typer.Exit(code=1)

    if output_json:
        console.print(json.dumps({
            "incident_id": record.incident_id,
            "state": record.state,
            "resolved_by": record.resolved_by,
            "state_note": record.state_note,
            "resolved_at": record.resolved_at.isoformat() if record.resolved_at else None,
        }, indent=2))
        return

    console.print(
        f"[bold green]✓[/bold green] Incident [bold]{record.incident_id}[/bold] "
        f"transitioned to [bold cyan]{record.state}[/bold cyan]"
        + (f"  (by {record.resolved_by})" if record.resolved_by else "")
    )


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _parse_dt(value: str, label: str) -> datetime.datetime:
    """Parse an ISO-8601 datetime string, exiting on failure."""
    for fmt in ("%Y-%m-%dT%H:%M:%S", "%Y-%m-%d"):
        try:
            return datetime.datetime.strptime(value, fmt).replace(tzinfo=datetime.UTC)
        except ValueError:
            continue
    console.print(f"[bold red]Error:[/bold red] Cannot parse {label}='{value}'. Use YYYY-MM-DD or YYYY-MM-DDTHH:MM:SS.")
    raise typer.Exit(code=1)


