"""FIN//GUARD CLI — Primary interface.

The CLI is the product. All security operations are accessible from
the terminal. A web/API layer may exist as an integration surface,
but the CLI must remain fully functional independently.

Usage:
    finguard status
    finguard key generate
    finguard identity list
    finguard agent-request tx create --from treasury --to vendor-a --amount 8000
    finguard tx create --from treasury --to vendor-a --amount 8000
    finguard attack suite
    finguard attest generate
    finguard attest verify attestation_report.json
"""

import sys
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text

# Force UTF-8 encoding on Windows streams
if sys.platform == "win32":
    if hasattr(sys.stdout, "reconfigure"):
        sys.stdout.reconfigure(encoding="utf-8")
    if hasattr(sys.stderr, "reconfigure"):
        sys.stderr.reconfigure(encoding="utf-8")

from finguard import __version__
from finguard.core.config import get_config
from finguard.identity.registry import IdentityRegistry
from finguard.storage.database import init_db, get_session
from finguard.storage.repositories import (
    TransactionRepository, ActorRepository, AuditRepository,
    IncidentRepository, KeyRepository,
)

console = Console()

# ── Main app ──────────────────────────────────────────────────────────
app = typer.Typer(
    name="finguard",
    help="FIN//GUARD — Autonomous AI Agent Transaction Security Firewall.",
    no_args_is_help=True,
    rich_markup_mode="rich",
)

# ── Subcommand groups ──────────────────────────────────────────────────
key_app = typer.Typer(help="Cryptographic key management.")
identity_app = typer.Typer(help="Identity & Authority Registry management.")
agent_request_app = typer.Typer(help="Constrained interface for autonomous AI agents.")
tx_app = typer.Typer(help="Transaction operations.")
policy_app = typer.Typer(help="Policy management and testing.")
approval_app = typer.Typer(help="Approval workflows.")
risk_app = typer.Typer(help="Risk analysis.")
attack_app = typer.Typer(help="Adversarial attack laboratory.")
attest_app = typer.Typer(help="Signed attestation reports.")
audit_app = typer.Typer(help="Tamper-evident audit ledger.")
incident_app = typer.Typer(help="Security incident management.")
decision_app = typer.Typer(help="Central authorization decision receipts.")
agent_app = typer.Typer(help="Untrusted treasury agent orchestration.")

app.add_typer(key_app, name="key")
app.add_typer(identity_app, name="identity")
app.add_typer(agent_request_app, name="agent-request")
app.add_typer(tx_app, name="tx")
app.add_typer(policy_app, name="policy")
app.add_typer(approval_app, name="approval")
app.add_typer(risk_app, name="risk")
app.add_typer(attack_app, name="attack")
app.add_typer(attest_app, name="attest")
app.add_typer(audit_app, name="audit")
app.add_typer(incident_app, name="incident")
app.add_typer(decision_app, name="decision")
app.add_typer(agent_app, name="agent")


@decision_app.command("inspect")
def decision_inspect(transaction_id: str = typer.Argument(help="Transaction ID.")):
    """Inspect the latest canonical decision receipt for a transaction."""
    _ensure_init()
    from finguard.storage.repositories import ReceiptRepository
    import json
    session = get_session()
    try:
        receipt = ReceiptRepository(session).get_by_transaction(transaction_id)
        if not receipt:
            raise typer.Exit(code=1)
        console.print(receipt.reason)
    finally:
        session.close()


@agent_app.command("run")
def agent_run(task: str = typer.Argument(help="Natural-language payment task.")):
    """Run the bounded treasury agent (never grants signing authority)."""
    _ensure_init()
    from finguard.agent import TreasuryAgent
    import json
    console.print(json.dumps(TreasuryAgent().run(task), indent=2))


@agent_app.command("status")
def agent_status():
    """Show the configured agent model state."""
    console.print("Treasury agent: bounded local fallback; model=not-configured")


def _ensure_init() -> None:
    """Initialize database and directories on first use."""
    config = get_config()
    config.ensure_dirs()
    init_db()
    # Initialize/verify identity registry
    IdentityRegistry()


# ── Status command ────────────────────────────────────────────────────
@app.command()
def status():
    """Show FIN//GUARD system status."""
    _ensure_init()
    config = get_config()
    session = get_session()

    tx_repo = TransactionRepository(session)
    audit_repo = AuditRepository(session)
    incident_repo = IncidentRepository(session)
    key_repo = KeyRepository(session)

    registry = IdentityRegistry()
    actors = registry.list_actors()

    tx_count = len(tx_repo.list_all(limit=999999))
    actor_count = len(actors)
    audit_count = audit_repo.count()
    incident_count = len(incident_repo.list_all(limit=999999))
    key_count = len(key_repo.list_all())

    session.close()

    header = Text()
    header.append("FIN//GUARD Firewall", style="bold cyan")
    header.append(f"  v{__version__}", style="dim")

    table = Table(show_header=False, box=None, padding=(0, 2))
    table.add_column("Field", style="bold")
    table.add_column("Value")

    table.add_row("Data directory", str(config.data_dir))
    table.add_row("Database", str(config.db_path))
    table.add_row("Identity Registry", "Signed identities.yaml (Valid ✓)")
    table.add_row("Registered Actors", str(actor_count))
    table.add_row("Stored Keys", str(key_count))
    table.add_row("Transactions", str(tx_count))
    table.add_row("Audit Ledger Entries", str(audit_count))
    table.add_row("Security Incidents", str(incident_count))

    console.print()
    console.print(Panel(table, title=str(header), border_style="cyan", padding=(1, 2)))
    console.print()


@app.command()
def init():
    """Initialize FIN//GUARD data directory, database, and root operator key."""
    _ensure_init()
    config = get_config()
    console.print(f"[green]✓[/green] Initialized FIN//GUARD at [cyan]{config.data_dir}[/cyan]")


@app.command()
def investigate(
    transaction_id: str = typer.Argument(help="Transaction ID to investigate."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Forensic investigation of a transaction."""
    _ensure_init()
    from finguard.cli.forensic_commands import do_investigate
    do_investigate(transaction_id, output_json)


# ── Key Commands ──────────────────────────────────────────────────────
@key_app.command("list")
def key_list():
    """List all stored keys."""
    _ensure_init()
    from finguard.cli.key_commands import do_key_list
    do_key_list()


@key_app.command("generate")
def key_generate(
    key_id: str = typer.Option(None, "--key-id", help="Custom key identifier."),
    passphrase: str = typer.Option(None, "--passphrase", help="Passphrase for non-interactive key generation."),
):
    """Generate a new Ed25519 signing keypair."""
    _ensure_init()
    from finguard.cli.key_commands import do_key_generate
    do_key_generate(key_id, passphrase)


@key_app.command("inspect")
def key_inspect(
    key_id: str = typer.Argument(help="Key identifier to inspect."),
):
    """Inspect a stored key."""
    _ensure_init()
    from finguard.cli.key_commands import do_key_inspect
    do_key_inspect(key_id)


# ── Identity Commands ─────────────────────────────────────────────────
@identity_app.command("list")
def identity_list():
    """List all registered identities and authority limits."""
    _ensure_init()
    from finguard.cli.identity_commands import do_identity_list
    do_identity_list()


@identity_app.command("show")
def identity_show(
    actor_id: str = typer.Argument(help="Actor ID to inspect."),
):
    """Show details of a specific identity."""
    _ensure_init()
    from finguard.cli.identity_commands import do_identity_show
    do_identity_show(actor_id)


@identity_app.command("register")
def identity_register(
    actor_id: str = typer.Option(..., "--actor-id", help="Actor ID."),
    actor_type: str = typer.Option(..., "--type", help="Actor type (human_operator or agent)."),
    display_name: str = typer.Option(..., "--name", help="Display name."),
    limit: float = typer.Option(10000.0, "--limit", help="Authority limit."),
    destinations: str = typer.Option("", "--destinations", help="Comma-separated allowed destinations."),
    root_key: str = typer.Option(..., "--root-key", help="Path to root operator private key."),
):
    """Register a new actor (requires root operator key to re-sign registry)."""
    _ensure_init()
    from finguard.cli.identity_commands import do_identity_register
    do_identity_register(actor_id, actor_type, display_name, limit, destinations, root_key)


# ── Agent Request Commands (Constrained Allowlist) ─────────────────────
@agent_request_app.command("tx-create")
def agent_tx_create(
    from_account: str = typer.Option(..., "--from", help="Source account."),
    to_account: str = typer.Option(..., "--to", help="Destination account."),
    amount: float = typer.Option(..., "--amount", help="Transaction amount."),
    currency: str = typer.Option("INR", "--currency", help="Currency code."),
    actor: str = typer.Option("treasury-agent", "--actor", help="Agent Actor ID."),
    session: str = typer.Option(None, "--session", help="Session ID."),
):
    """Submit a transaction request as an autonomous AI Agent."""
    _ensure_init()
    from finguard.cli.agent_commands import do_agent_tx_create
    do_agent_tx_create(from_account, to_account, amount, currency, actor, session)


# ── Transaction Commands ──────────────────────────────────────────────
@tx_app.command("create")
def tx_create(
    from_account: str = typer.Option(..., "--from", help="Source account."),
    to_account: str = typer.Option(..., "--to", help="Destination account."),
    amount: float = typer.Option(..., "--amount", help="Transaction amount."),
    currency: str = typer.Option("INR", "--currency", help="Currency code."),
    actor: str = typer.Option(None, "--actor", help="Actor ID."),
    metadata: str = typer.Option(None, "--metadata", help="JSON metadata."),
):
    """Create a new transaction request as an operator."""
    _ensure_init()
    from finguard.cli.transaction_commands import do_tx_create
    do_tx_create(from_account, to_account, amount, currency, actor, metadata)


@tx_app.command("inspect")
def tx_inspect(
    transaction_id: str = typer.Argument(help="Transaction ID."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Inspect a transaction."""
    _ensure_init()
    from finguard.cli.transaction_commands import do_tx_inspect
    do_tx_inspect(transaction_id, output_json)


@tx_app.command("sign")
def tx_sign(
    transaction_id: str = typer.Argument(help="Transaction ID to sign."),
    key_id: str = typer.Option(None, "--key-id", help="Signing key ID."),
):
    """Sign a transaction."""
    _ensure_init()
    from finguard.cli.transaction_commands import do_tx_sign
    do_tx_sign(transaction_id, key_id)


@tx_app.command("verify")
def tx_verify(
    transaction_id: str = typer.Argument(help="Transaction ID to verify."),
):
    """Verify a transaction signature."""
    _ensure_init()
    from finguard.cli.transaction_commands import do_tx_verify
    do_tx_verify(transaction_id)


@tx_app.command("list")
def tx_list(
    state: str = typer.Option(None, "--state", help="Filter by state."),
    limit: int = typer.Option(20, "--limit", help="Max results."),
):
    """List transactions."""
    _ensure_init()
    from finguard.cli.transaction_commands import do_tx_list
    do_tx_list(state, limit)


# ── Policy Commands ───────────────────────────────────────────────────
@policy_app.command("validate")
def policy_validate(
    path: str = typer.Argument(help="Path to policy YAML file."),
):
    """Validate a YAML policy file."""
    _ensure_init()
    from finguard.cli.policy_commands import do_policy_validate
    do_policy_validate(path)


@policy_app.command("test")
def policy_test(
    path: str = typer.Argument(help="Path to policy YAML file."),
):
    """Test a policy against synthetic test suite."""
    _ensure_init()
    from finguard.cli.policy_commands import do_policy_test
    do_policy_test(path)


# ── Approval Commands ─────────────────────────────────────────────────
@approval_app.command("list")
def approval_list():
    """List pending transaction approval requests."""
    _ensure_init()
    from finguard.cli.approval_commands import do_approval_list
    do_approval_list()


@approval_app.command("approve")
def approval_approve(
    transaction_id: str = typer.Argument(help="Transaction ID to approve."),
    approver: str = typer.Option(None, "--approver", help="Approver actor ID."),
    key_id: str = typer.Option(None, "--key-id", help="Approver key ID."),
):
    """Approve a pending transaction."""
    _ensure_init()
    from finguard.cli.approval_commands import do_approval_approve
    do_approval_approve(transaction_id, approver, key_id)


# ── Risk Commands ─────────────────────────────────────────────────────
@risk_app.command("analyze")
def risk_analyze(
    transaction_id: str = typer.Argument(help="Transaction ID."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Analyze risk signals for a transaction."""
    _ensure_init()
    from finguard.cli.risk_commands import do_risk_analyze
    do_risk_analyze(transaction_id, output_json)


# ── Attack Commands ───────────────────────────────────────────────────
@attack_app.command("list")
def attack_list():
    """List available declarative attack scenarios."""
    _ensure_init()
    from finguard.cli.attack_commands import do_attack_list
    do_attack_list()


@attack_app.command("run")
def attack_run(
    scenario: str = typer.Argument(help="Attack scenario name."),
):
    """Run an attack scenario."""
    _ensure_init()
    from finguard.cli.attack_commands import do_attack_run
    do_attack_run(scenario)


@attack_app.command("suite")
def attack_suite():
    """Run full attack suite and generate adversarial benchmark report."""
    _ensure_init()
    from finguard.cli.attack_commands import do_attack_suite
    do_attack_suite()


# ── Attestation Commands ──────────────────────────────────────────────
@attest_app.command("generate")
def attest_generate(
    output: str = typer.Option(None, "--output", "-o", help="Output report JSON file path."),
):
    """Generate a signed AttestationReport JSON artifact."""
    _ensure_init()
    from finguard.cli.attestation_commands import do_attest_generate
    do_attest_generate(output)


@attest_app.command("verify")
def attest_verify(
    report_path: str = typer.Argument(help="Path to AttestationReport JSON file."),
):
    """Verify an AttestationReport JSON artifact."""
    _ensure_init()
    from finguard.cli.attestation_commands import do_attest_verify
    do_attest_verify(report_path)


# ── Audit Commands ────────────────────────────────────────────────────
@audit_app.command("show")
def audit_show(
    limit: int = typer.Option(20, "--limit", help="Max entries."),
):
    """Show recent audit entries."""
    _ensure_init()
    from finguard.cli.audit_commands import do_audit_show
    do_audit_show(limit)


@audit_app.command("verify")
def audit_verify():
    """Verify audit ledger hash chain integrity."""
    _ensure_init()
    from finguard.cli.audit_commands import do_audit_verify
    do_audit_verify()


@audit_app.command("export")
def audit_export(
    format: str = typer.Option("json", "--format", help="Export format: json or csv."),
    output: str = typer.Option(None, "--output", "-o", help="Output file path."),
):
    """Export audit ledger."""
    _ensure_init()
    from finguard.cli.audit_commands import do_audit_export
    do_audit_export(format, output)


# ── Incident Commands ─────────────────────────────────────────────────
@incident_app.command("list")
def incident_list():
    """List security incidents."""
    _ensure_init()
    from finguard.cli.incident_commands import do_incident_list
    do_incident_list()


@incident_app.command("show")
def incident_show(
    incident_id: str = typer.Argument(help="Incident ID."),
    output_json: bool = typer.Option(False, "--json", help="Output as JSON."),
):
    """Show incident details."""
    _ensure_init()
    from finguard.cli.incident_commands import do_incident_show
    do_incident_show(incident_id, output_json)


if __name__ == "__main__":
    app()
