"""CLI commands for adversarial attack laboratory."""

import typer
from rich.console import Console
from rich.panel import Panel
from rich.table import Table

from finguard.attacks.scenario_loader import ScenarioLoader

console = Console()


def do_attack_list():
    """List available declarative attack scenarios."""
    loader = ScenarioLoader()
    scenarios = loader.list_scenarios()

    if not scenarios:
        console.print("[yellow]No attack scenarios found.[/yellow]")
        return

    table = Table(title="FIN//GUARD Adversarial Attack Laboratory", border_style="cyan")
    table.add_column("Scenario Name", style="bold cyan")
    table.add_column("Type", style="white")

    for s in scenarios:
        table.add_row(s, "Declarative YAML Scenario")

    console.print(table)


def do_attack_run(scenario_name: str):
    """Run an attack scenario against the live security pipeline."""
    loader = ScenarioLoader()
    try:
        res = loader.run_scenario(scenario_name)

        status_color = "green" if res.passed else "red"
        status_text = "PASSED (BLOCKED)" if res.passed else "FAILED (NOT BLOCKED)"

        console.print()
        console.print(Panel(
            f"Scenario:     [bold white]{res.scenario_name}[/bold white]\n"
            f"Description:  {res.description}\n"
            f"Outcome:      [{status_color}]{status_text}[/{status_color}]\n"
            f"Incident ID:  [yellow]{res.incident_id or 'None'}[/yellow]\n"
            f"Orig Hash:    [dim]{res.original_hash or 'N/A'}[/dim]\n"
            f"Mod Hash:     [dim]{res.modified_hash or 'N/A'}[/dim]",
            title="Attack Scenario Execution Result",
            border_style=status_color
        ))

        console.print("\n[bold]Execution Trace:[/bold]")
        for line in res.explanation_trace:
            console.print(f"  {line}")

        console.print("\n[bold]Step Summary:[/bold]")
        for step in res.step_results:
            step_color = "green" if step.passed else "red"
            console.print(f"  [{step_color}]✓[/{step_color}] Step {step.step_index} [{step.action}]: {step.details}")

    except Exception as e:
        console.print(f"[bold red]Error executing attack scenario:[/bold red] {e}")
        raise typer.Exit(code=1)


def do_attack_suite():
    """Run full attack suite and generate adversarial benchmark report."""
    loader = ScenarioLoader()
    scenarios = loader.list_scenarios()

    console.print(f"[bold cyan]Executing FIN//GUARD Adversarial Attack Suite ({len(scenarios)} scenarios)...[/bold cyan]\n")

    table = Table(title="FIN//GUARD Adversarial Benchmark Report", border_style="cyan")
    table.add_column("Scenario", style="bold white")
    table.add_column("Defense Outcome", style="bold")
    table.add_column("Incident ID", style="yellow")
    table.add_column("Details", style="dim")

    passed_count = 0

    for s in scenarios:
        try:
            res = loader.run_scenario(s)
            if res.passed:
                passed_count += 1
                outcome = "[bold green]BLOCKED (PASS)[/bold green]"
            else:
                outcome = "[bold red]EXPLOITED (FAIL)[/bold red]"

            details = res.step_results[-1].details if res.step_results else "No details"
            table.add_row(s, outcome, res.incident_id or "N/A", details[:60])
        except Exception as e:
            table.add_row(s, "[bold red]ERROR[/bold red]", "N/A", str(e))

    console.print(table)
    console.print(f"\n[bold green]Suite Completed:[/bold green] {passed_count}/{len(scenarios)} attack vectors successfully defended.")
