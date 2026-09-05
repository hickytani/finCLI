"""CLI commands for transaction creation, inspection, signing, and verification."""

import json
import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.prompt import Prompt

from finguard.approvals.service import ApprovalService
from finguard.audit.ledger import AuditLedger
from finguard.audit.nonce_store import NonceStore
from finguard.core.enums import Currency, TransactionState, DecisionType, IncidentSeverity
from finguard.core.transaction import Transaction
from finguard.crypto.keystore import Keystore
from finguard.crypto.signing import sign_canonical_bytes, verify_signature
from finguard.identity.registry import IdentityRegistry
from finguard.incidents.service import IncidentService
from finguard.policy.engine import PolicyEngine
from finguard.risk.engine import RiskEngine
from finguard.storage.database import get_session
from finguard.storage.models import TransactionRecord, ActorRecord
from finguard.storage.repositories import TransactionRepository, ActorRepository

console = Console()


def do_tx_create(
    from_account: str,
    to_account: str,
    amount: float,
    currency: str = "INR",
    actor_id: str | None = None,
    metadata_json: str | None = None
):
    """Create a new financial transaction request as an operator."""
    # Phase 2: all creation paths enter through the central decision engine.
    from finguard.decision import DecisionEngine
    actor_id = actor_id or "operator-1"
    registry = IdentityRegistry()
    actor = registry.get_actor(actor_id)
    if not actor:
        raise typer.BadParameter(f"Unknown actor '{actor_id}'")
    tx = Transaction(
        actor_id=actor_id, from_account=from_account, to_account=to_account,
        amount=amount, currency=Currency(currency.upper()),
        metadata=json.loads(metadata_json) if metadata_json else None,
        initiating_actor_type=actor.actor_type.value,
    )
    result = DecisionEngine(registry=registry).decide(tx)
    console.print(Panel(
        f"Transaction ID: [bold cyan]{tx.transaction_id}[/bold cyan]\n"
        f"Decision: [bold]{result.decision.value.upper()}[/bold]\n"
        f"Receipt: [dim]{result.receipt.receipt_id}[/dim]\n"
        f"Reason: [dim]{'; '.join(result.receipt.reasons)}[/dim]",
        title="Transaction Processed", border_style="cyan",
    ))
    return result

    actor_id = actor_id or "operator-1"
    registry = IdentityRegistry()
    actor = registry.get_actor(actor_id)

    if not actor:
        actor = registry.validate_actor("operator-1")

    meta = json.loads(metadata_json) if metadata_json else None

    tx = Transaction(
        actor_id=actor_id,
        from_account=from_account,
        to_account=to_account,
        amount=amount,
        currency=Currency(currency.upper()),
        metadata=meta,
        initiating_actor_type=actor.actor_type.value
    )

    # 1. Nonce Replay Protection
    nonce_store = NonceStore()
    if nonce_store.has_used(tx.nonce):
        inc_service = IncidentService()
        inc_service.create_incident(
            severity=IncidentSeverity.CRITICAL,
            description=f"Transaction replay attempt detected for nonce '{tx.nonce}'",
            transaction_id=tx.transaction_id,
            actor_id=actor_id,
            signals=["REPLAY_ATTEMPT"],
            decision="BLOCK"
        )
        console.print(f"[bold red]REPLAY DETECTED:[/bold red] Nonce '{tx.nonce}' already used.")
        raise typer.Exit(code=1)

    nonce_store.record(tx.nonce, tx.transaction_id)

    # 2. Risk Analysis
    risk_engine = RiskEngine()
    risk_res = risk_engine.analyze(tx, actor)

    # 3. Policy Evaluation
    policy_engine = PolicyEngine()
    pol_res = policy_engine.evaluate(tx, actor, risk_res.model_dump())

    if pol_res.decision_type == DecisionType.BLOCK:
        tx.state = TransactionState.BLOCKED
        inc_service = IncidentService()
        inc_service.create_incident(
            severity=IncidentSeverity.HIGH,
            description=f"Transaction blocked by policy: {pol_res.explanation}",
            transaction_id=tx.transaction_id,
            actor_id=actor_id,
            signals=risk_res.signals,
            decision="BLOCK"
        )
        need_approval = False
    elif pol_res.decision_type == DecisionType.REQUIRE_APPROVAL:
        tx.state = TransactionState.PENDING_APPROVAL
        need_approval = True
    else:
        tx.state = TransactionState.CREATED
        need_approval = False

    # 4. Persist transaction FIRST (so FK constraint is satisfied for approval_requests)
    session = get_session()
    try:
        actor_repo = ActorRepository(session)
        if not actor_repo.get(actor_id):
            actor_repo.save(ActorRecord(
                actor_id=actor.actor_id,
                actor_type=actor.actor_type.value,
                display_name=actor.display_name,
                active=True
            ))

        tx_repo = TransactionRepository(session)
        rec = TransactionRecord(
            transaction_id=tx.transaction_id,
            actor_id=tx.actor_id,
            session_id=tx.session_id,
            from_account=tx.from_account,
            to_account=tx.to_account,
            amount=tx.amount,
            currency=tx.currency.value,
            nonce=tx.nonce,
            timestamp=tx.timestamp,
            metadata_json=json.dumps(tx.metadata) if tx.metadata else None,
            state=tx.state.value,
            canonical_hash=tx.transaction_hash(),
        )
        tx_repo.save(rec)
    finally:
        session.close()

    # 5. Now create approval request (transaction is already in DB)
    if need_approval:
        appr_service = ApprovalService()
        appr_service.create_approval_request(
            transaction=tx,
            required_approvals=pol_res.required_approvals,
            requester_id=actor_id
        )

    # Audit entry
    audit = AuditLedger()
    audit.append(
        action="TX_CREATE",
        actor_id=actor_id,
        transaction_id=tx.transaction_id,
        result=tx.state.value.upper(),
        metadata={
            "amount": tx.amount,
            "to_account": tx.to_account,
            "risk_score": risk_res.risk_score,
            "policy": pol_res.decision_type.value
        }
    )

    color = "green" if tx.state == TransactionState.CREATED else ("yellow" if tx.state == TransactionState.PENDING_APPROVAL else "red")

    console.print(Panel(
        f"Transaction ID: [bold cyan]{tx.transaction_id}[/bold cyan]\n"
        f"Actor:          [white]{tx.actor_id}[/white]\n"
        f"Transfer:       [white]{tx.from_account}[/white] ➔ [white]{tx.to_account}[/white]\n"
        f"Amount:         [bold yellow]{tx.currency.value} {tx.amount:,.2f}[/bold yellow]\n"
        f"State:          [{color}]{tx.state.value.upper()}[/{color}]\n"
        f"Policy Trace:   [dim]{pol_res.explanation}[/dim]\n"
        f"Canonical Hash: [dim]{tx.transaction_hash()}[/dim]",
        title="Transaction Processed",
        border_style="cyan"
    ))


def do_tx_inspect(transaction_id: str, output_json: bool = False):
    """Inspect a transaction record by ID."""
    session = get_session()
    try:
        tx_repo = TransactionRepository(session)
        rec = tx_repo.get(transaction_id)
        if not rec:
            console.print(f"[bold red]Error:[/bold red] Transaction '{transaction_id}' not found.")
            raise typer.Exit(code=1)

        data = {
            "transaction_id": rec.transaction_id,
            "actor_id": rec.actor_id,
            "session_id": rec.session_id,
            "from_account": rec.from_account,
            "to_account": rec.to_account,
            "amount": rec.amount,
            "currency": rec.currency,
            "nonce": rec.nonce,
            "timestamp": rec.timestamp.isoformat(),
            "state": rec.state,
            "canonical_hash": rec.canonical_hash,
            "signature": rec.signature,
            "signing_key_id": rec.signing_key_id,
        }

        if output_json:
            console.print(json.dumps(data, indent=2))
            return

        table = Table(title=f"Transaction details: {transaction_id}", border_style="cyan", show_header=False)
        table.add_column("Field", style="bold white")
        table.add_column("Value")

        for k, v in data.items():
            table.add_row(k, str(v) if v is not None else "[dim]none[/dim]")

        console.print(table)
    finally:
        session.close()


def do_tx_sign(transaction_id: str, key_id: str | None = None):
    """Sign a transaction (verifying identity, authority, policy, risk, approvals, and integrity)."""
    # The legacy signer below is deliberately unreachable: all application
    # signing must use the final gate and its immediate revalidation.
    from finguard.signing import SigningGate
    if not key_id:
        keys = Keystore().list_keys()
        if not keys:
            console.print("[bold red]Error:[/bold red] No keys found in keystore.")
            raise typer.Exit(code=1)
        key_id = keys[0]["key_id"]
    password = Prompt.ask(f"Enter passphrase for key '{key_id}'", password=True)
    try:
        signature = SigningGate().sign(transaction_id, key_id, password)
        console.print(f"[bold green]✓ Transaction '{transaction_id}' successfully signed by the final signing gate.[/bold green]")
        console.print(f"Signature: [dim]{signature}[/dim]")
        return signature
    except Exception as e:
        console.print(f"[bold red]SIGNING BLOCKED:[/bold red] {e}")
        raise typer.Exit(code=1)

    session = get_session()
    try:
        tx_repo = TransactionRepository(session)
        rec = tx_repo.get(transaction_id)
        if not rec:
            console.print(f"[bold red]Error:[/bold red] Transaction '{transaction_id}' not found.")
            raise typer.Exit(code=1)

        if rec.state == TransactionState.BLOCKED.value:
            console.print("[bold red]Error:[/bold red] Cannot sign a BLOCKED transaction.")
            raise typer.Exit(code=1)

        if rec.state == TransactionState.SIGNED.value:
            console.print("[bold yellow]Notice:[/bold yellow] Transaction is already signed.")
            return

        tx = Transaction(
            transaction_id=rec.transaction_id,
            actor_id=rec.actor_id,
            session_id=rec.session_id,
            from_account=rec.from_account,
            to_account=rec.to_account,
            amount=rec.amount,
            currency=Currency(rec.currency),
            nonce=rec.nonce,
            timestamp=rec.timestamp,
            state=TransactionState(rec.state)
        )

        # Check hash tampering vs stored record
        if rec.canonical_hash != tx.transaction_hash():
            rec.state = TransactionState.BLOCKED.value
            tx_repo.save(rec)
            inc_service = IncidentService()
            inc = inc_service.create_incident(
                severity=IncidentSeverity.CRITICAL,
                description=f"Transaction tampering detected during signing for '{transaction_id}'",
                transaction_id=transaction_id,
                actor_id=rec.actor_id,
                signals=["TAMPERING_DETECTED", "HASH_MISMATCH"],
                decision="BLOCK"
            )
            console.print(f"[bold red]TAMPERING DETECTED:[/bold red] Transaction hash mismatch! Incident {inc.incident_id}")
            raise typer.Exit(code=1)

        # Check approval requirement
        if rec.state == TransactionState.PENDING_APPROVAL.value:
            appr_service = ApprovalService(session=session)
            if not appr_service.verify_approval_integrity(tx):
                console.print(f"[bold red]SIGNING BLOCKED:[/bold red] Transaction '{transaction_id}' requires valid human operator approval.")
                raise typer.Exit(code=1)

        keystore = Keystore()
        if not key_id:
            keys = keystore.list_keys()
            if not keys:
                console.print("[bold red]Error:[/bold red] No keys found in keystore. Run 'finguard key generate' first.")
                raise typer.Exit(code=1)
            key_id = keys[0]["key_id"]

        password = Prompt.ask(f"Enter passphrase for key '{key_id}'", password=True)

        try:
            priv_key = keystore.load_private_key(key_id, password)
            canonical_bytes = tx.canonical_bytes()
            signature = sign_canonical_bytes(canonical_bytes, priv_key)

            rec.signature = signature
            rec.signing_key_id = key_id
            rec.state = TransactionState.SIGNED.value
            tx_repo.save(rec)

            audit = AuditLedger()
            audit.append(
                action="TX_SIGN",
                actor_id=rec.actor_id,
                transaction_id=rec.transaction_id,
                result="SIGNED",
                metadata={"key_id": key_id, "hash": tx.transaction_hash()}
            )

            console.print(f"[bold green]✓ Transaction '{transaction_id}' successfully signed![/bold green]")
            console.print(f"Signing Key ID: [cyan]{key_id}[/cyan]")
            console.print(f"Signature:      [dim]{signature}[/dim]")

        except Exception as e:
            console.print(f"[bold red]Signing Error:[/bold red] {e}")
            raise typer.Exit(code=1)

    finally:
        session.close()


def do_tx_verify(transaction_id: str):
    """Verify cryptographic signature on a signed transaction."""
    session = get_session()
    try:
        tx_repo = TransactionRepository(session)
        rec = tx_repo.get(transaction_id)
        if not rec:
            console.print(f"[bold red]Error:[/bold red] Transaction '{transaction_id}' not found.")
            raise typer.Exit(code=1)

        if not rec.signature or not rec.signing_key_id:
            console.print(f"[bold red]Error:[/bold red] Transaction '{transaction_id}' has not been signed yet.")
            raise typer.Exit(code=1)

        tx = Transaction(
            transaction_id=rec.transaction_id,
            actor_id=rec.actor_id,
            session_id=rec.session_id,
            from_account=rec.from_account,
            to_account=rec.to_account,
            amount=rec.amount,
            currency=Currency(rec.currency),
            nonce=rec.nonce,
            timestamp=rec.timestamp,
            state=TransactionState(rec.state)
        )

        keystore = Keystore()
        try:
            pub_hex = keystore.get_public_key(rec.signing_key_id)
            pub_bytes = bytes.fromhex(pub_hex)
            verify_signature(tx.canonical_bytes(), rec.signature, pub_bytes)

            console.print(f"[bold green]✓ SIGNATURE VALID[/bold green]")
            console.print(f"Transaction ID: [cyan]{transaction_id}[/cyan]")
            console.print(f"Signing Key:    [cyan]{rec.signing_key_id}[/cyan]")
            console.print(f"Canonical Hash: [dim]{tx.transaction_hash()}[/dim]")
        except Exception as e:
            console.print(f"[bold red]✗ SIGNATURE INVALID / INTEGRITY FAILURE:[/bold red] {e}")
            raise typer.Exit(code=1)

    finally:
        session.close()


def do_tx_list(state: str | None = None, limit: int = 20):
    """List recent transactions."""
    session = get_session()
    try:
        tx_repo = TransactionRepository(session)
        if state:
            records = tx_repo.list_by_state(state, limit=limit)
        else:
            records = tx_repo.list_all(limit=limit)

        if not records:
            console.print("[yellow]No transactions found.[/yellow]")
            return

        table = Table(title="FIN//GUARD Transactions", border_style="cyan")
        table.add_column("TX ID", style="bold white")
        table.add_column("Actor", style="cyan")
        table.add_column("From ➔ To", style="white")
        table.add_column("Amount", style="yellow")
        table.add_column("State", style="bold")
        table.add_column("Signed", style="magenta")

        for r in records:
            state_color = "green" if r.state == "signed" else ("red" if r.state == "blocked" else "yellow")
            table.add_row(
                r.transaction_id,
                r.actor_id,
                f"{r.from_account} ➔ {r.to_account}",
                f"{r.currency} {r.amount:,.2f}",
                f"[{state_color}]{r.state.upper()}[/{state_color}]",
                "✓" if r.signature else "✗"
            )

        console.print(table)
    finally:
        session.close()
