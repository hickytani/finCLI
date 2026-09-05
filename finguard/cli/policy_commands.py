"""CLI commands for policy validation and testing."""

from pathlib import Path
import typer
from rich.console import Console
from rich.panel import Panel

from finguard.core.enums import Currency, ActorType
from finguard.core.transaction import Transaction
from finguard.identity.registry import ActorConfig
from finguard.policy.parser import load_policy_from_yaml
from finguard.policy.engine import PolicyEngine

console = Console()


def do_policy_validate(path: str):
    """Validate syntax and schema of a YAML policy file."""
    try:
        policy = load_policy_from_yaml(path)
        console.print(f"[bold green]✓ Policy file '{path}' is VALID.[/bold green]")
        console.print(f"Policy ID:  [cyan]{policy.policy_id}[/cyan]")
        console.print(f"Version:    [cyan]{policy.version}[/cyan]")
        console.print(f"Description:[white]{policy.description or 'None'}[/white]")
    except Exception as e:
        console.print(f"[bold red]✗ INVALID POLICY FILE:[/bold red] {e}")
        raise typer.Exit(code=1)


def do_policy_test(path: str):
    """Test a YAML policy against standard synthetic transactions."""
    try:
        policy = load_policy_from_yaml(path)
        engine = PolicyEngine(policy)

        # Test cases
        test_actor = ActorConfig(
            actor_id="treasury-agent",
            actor_type=ActorType.AGENT,
            display_name="Test Agent",
            authority_limit=10000.0,
            allowed_destinations=["vendor-a", "vendor-b"]
        )

        sample_txs = [
            ("Legitimate Agent Tx", Transaction(actor_id="treasury-agent", from_account="treasury", to_account="vendor-a", amount=5000.0)),
            ("Over-limit Tx", Transaction(actor_id="treasury-agent", from_account="treasury", to_account="vendor-a", amount=50000.0)),
            ("Unauthorized Dest Tx", Transaction(actor_id="treasury-agent", from_account="treasury", to_account="evil-corp", amount=1000.0)),
        ]

        console.print(f"[bold cyan]Testing Policy '{policy.policy_id}' against synthetic test suite:[/bold cyan]\n")

        for label, tx in sample_txs:
            decision = engine.evaluate(tx, test_actor)
            color = "green" if decision.allowed else ("yellow" if decision.decision_type.value == "require_approval" else "red")
            console.print(Panel(
                f"Test:               [bold white]{label}[/bold white]\n"
                f"Amount & Target:    {tx.currency.value} {tx.amount:,.2f} ➔ {tx.to_account}\n"
                f"Decision:           [{color}]{decision.decision_type.value.upper()}[/{color}]\n"
                f"Required Approvals: [bold]{decision.required_approvals}[/bold]\n"
                f"Explanation:        [dim]{decision.explanation}[/dim]",
                border_style="cyan"
            ))

    except Exception as e:
        console.print(f"[bold red]Error testing policy:[/bold red] {e}")
        raise typer.Exit(code=1)
