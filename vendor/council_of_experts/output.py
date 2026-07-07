"""Rich terminal output formatting."""

from __future__ import annotations

from typing import TYPE_CHECKING

from rich.console import Console
from rich.panel import Panel
from rich.progress import Progress, SpinnerColumn, TextColumn
from rich.table import Table
from rich.tree import Tree

if TYPE_CHECKING:
    from council_of_experts.schemas import CouncilResult, ExpertResponse, GuidanceOutput


console = Console()


def print_header(title: str) -> None:
    """Print a styled header."""
    console.print()
    console.print(Panel(title, style="bold blue"))


def print_expert_status(name: str, available: bool, model: str = "") -> None:
    """Print expert availability status."""
    status = "[green]✓ Available[/green]" if available else "[red]✗ Not Found[/red]"
    model_str = f" ({model})" if model else ""
    console.print(f"  {name}{model_str}: {status}")


def print_experts_table(experts: list[tuple[str, bool, str]]) -> None:
    """Print a table of experts and their status."""
    table = Table(title="Available Experts")
    table.add_column("Expert", style="cyan")
    table.add_column("Status", style="green")
    table.add_column("Model", style="yellow")

    for name, available, model in experts:
        status = "✓ Available" if available else "✗ Not Found"
        style = "green" if available else "red"
        table.add_row(name, f"[{style}]{status}[/{style}]", model)

    console.print(table)


def print_generation_progress(experts: list[str]) -> Progress:
    """Create a progress bar for generation."""
    return Progress(
        SpinnerColumn(),
        TextColumn("[progress.description]{task.description}"),
        console=console,
    )


def print_response_summary(response: ExpertResponse) -> None:
    """Print a summary of an expert's response."""
    console.print(f"\n[bold]{response.expert_name}[/bold] ({response.model})")
    console.print(f"  Time: {response.generation_time:.1f}s")
    console.print(f"  PRs evaluated: {len(response.guidance.pr_evaluations)}")
    console.print(f"  Triage accuracy: {response.guidance.triage_accuracy:.1%}")
    console.print(f"  Fix completeness: {response.guidance.fix_completeness:.1%}")
    triage_updates = len(response.guidance.triage_guideline_updates)
    remediation_updates = len(response.guidance.remediation_guideline_updates)
    console.print(
        f"  Guideline updates: {triage_updates} triage, {remediation_updates} remediation"
    )


def print_council_result(result: CouncilResult) -> None:
    """Print the final council result."""
    console.print()
    console.print(Panel("[bold]Council Result[/bold]", style="green"))

    # Agreement score
    score = result.agreement_score
    if score >= 0.8:
        score_style = "green"
    elif score >= 0.5:
        score_style = "yellow"
    else:
        score_style = "red"
    console.print(f"Agreement Score: [{score_style}]{score:.1%}[/{score_style}]")

    # Conflicts
    console.print(f"Conflicts Resolved: {result.conflicts_resolved}")
    if result.conflicts_manual > 0:
        console.print(f"[yellow]Conflicts Needing Review: {result.conflicts_manual}[/yellow]")

    console.print(f"Reconciliation Rounds: {result.reconciliation_rounds}")

    # Expert contributions
    console.print("\n[bold]Expert Contributions:[/bold]")
    for expert, contrib in result.expert_contributions.items():
        console.print(f"  {expert}: {contrib:.1%}")

    # Guidance summary
    guidance = result.guidance
    console.print("\n[bold]Evaluation Summary:[/bold]")
    console.print(f"  PR Evaluations: {len(guidance.pr_evaluations)}")
    console.print(f"  Triage Accuracy: {guidance.triage_accuracy:.1%}")
    console.print(f"  Fix Completeness: {guidance.fix_completeness:.1%}")

    console.print("\n[bold]Guideline Updates:[/bold]")
    console.print(f"  Triage Updates: {len(guidance.triage_guideline_updates)}")
    console.print(f"  Remediation Updates: {len(guidance.remediation_guideline_updates)}")

    if guidance.lessons_learned:
        console.print("\n[bold]Lessons Learned:[/bold]")
        for lesson in guidance.lessons_learned[:5]:  # Show top 5
            console.print(f"  • {lesson}")


def print_audit_tree(result: CouncilResult) -> None:
    """Print an audit tree of conflict resolutions."""
    if not result.audit_trail:
        console.print("[dim]No conflicts to show[/dim]")
        return

    tree = Tree("[bold]Conflict Resolution Audit[/bold]")

    for conflict in result.audit_trail:
        method_style = {
            "unanimous": "green",
            "majority": "blue",
            "tiebreaker": "yellow",
            "first": "red",
        }.get(conflict.resolution_method, "white")

        node = tree.add(f"[{method_style}]{conflict.field_path}[/{method_style}]")
        node.add(f"Method: {conflict.resolution_method}")
        if conflict.tiebreaker_expert:
            node.add(f"Tiebreaker: {conflict.tiebreaker_expert}")

        values_node = node.add("Values:")
        for expert, value in conflict.expert_values.items():
            val_str = str(value)[:50] + "..." if len(str(value)) > 50 else str(value)
            values_node.add(f"{expert}: {val_str}")

    console.print(tree)


def _print_council_status(merged: dict, status: dict) -> None:
    """Print the shared council/arbiter/degradation footer."""
    console.print(f"\n[bold]Council:[/bold] {', '.join(merged.get('council', []))}"
                  f"   [bold]Arbiter:[/bold] {merged.get('arbiter')}")
    if status.get("degraded"):
        print_warning(f"Degraded run: {status.get('error') or status.get('experts')}")


def _print_disagreements(merged: dict) -> None:
    """Print arbiter-resolved disagreements, if any."""
    disagreements = merged.get("disagreements") or []
    if not disagreements:
        console.print("\n[green]Experts agreed — no arbiter rulings needed.[/green]")
        return

    console.print(f"\n[bold]Arbiter-resolved disagreements ({len(disagreements)}):[/bold]")
    for d in disagreements:
        if not isinstance(d, dict):
            console.print(f"  • {d}")
            continue
        console.print(f"  • [yellow]{d.get('topic', '(unspecified)')}[/yellow] "
                      f"→ {d.get('ruling', '?')}")
        for expert_name, stance in (d.get("positions") or {}).items():
            console.print(f"      {expert_name}: {stance}")
        if d.get("rationale"):
            console.print(f"      [dim]{d['rationale']}[/dim]")


def print_ask_result(merged: dict, status: dict, list_key: str | None) -> None:
    """Print a consensus answer from `council ask`."""
    console.print()
    console.print(Panel("[bold]Council Consensus[/bold]", style="green"))

    if list_key:
        items = merged.get(list_key) or []
        for it in items:
            if isinstance(it, dict):
                head = it.get("point") or it.get("title") or next(iter(it.values()), "")
                agreement = it.get("agreement", "")
                tag = f" [dim]({agreement})[/dim]" if agreement else ""
                console.print(f"  • {head}{tag}")
                if it.get("detail"):
                    console.print(f"    [dim]{it['detail']}[/dim]")
            else:
                console.print(f"  • {it}")
    else:
        consensus = merged.get("consensus") or {}
        if consensus.get("answer"):
            console.print(consensus["answer"])
        if consensus.get("key_points"):
            console.print("\n[bold]Key points:[/bold]")
            for point in consensus["key_points"]:
                console.print(f"  • {point}")
        if consensus.get("confidence"):
            console.print(f"\n[bold]Confidence:[/bold] {consensus['confidence']}")
        if not consensus.get("answer") and not consensus.get("key_points"):
            # Custom schema: show the whole consensus document.
            import json
            console.print_json(json.dumps(consensus, default=str))

    _print_disagreements(merged)
    _print_council_status(merged, status)


def print_arbiter_result(
    merged: dict, status: dict, guidance: GuidanceOutput | None
) -> None:
    """Print an arbiter-consensus result from `council generate`."""
    console.print()
    console.print(Panel("[bold]Council Result (arbiter consensus)[/bold]", style="green"))

    if guidance is not None:
        console.print("\n[bold]Evaluation Summary:[/bold]")
        console.print(f"  PR Evaluations: {len(guidance.pr_evaluations)}")
        console.print(f"  Triage Accuracy: {guidance.triage_accuracy:.1%}")
        console.print(f"  Fix Completeness: {guidance.fix_completeness:.1%}")
        console.print("\n[bold]Guideline Updates:[/bold]")
        console.print(f"  Triage Updates: {len(guidance.triage_guideline_updates)}")
        console.print(f"  Remediation Updates: {len(guidance.remediation_guideline_updates)}")
        if guidance.lessons_learned:
            console.print("\n[bold]Lessons Learned:[/bold]")
            for lesson in guidance.lessons_learned[:5]:
                console.print(f"  • {lesson}")
    else:
        print_warning("Consensus did not validate as GuidanceOutput; showing raw consensus.")
        import json
        console.print_json(json.dumps(merged.get("consensus") or {}, default=str))

    _print_disagreements(merged)
    _print_council_status(merged, status)


def print_error(message: str) -> None:
    """Print an error message."""
    console.print(f"[bold red]Error:[/bold red] {message}")


def print_success(message: str) -> None:
    """Print a success message."""
    console.print(f"[bold green]✓[/bold green] {message}")


def print_warning(message: str) -> None:
    """Print a warning message."""
    console.print(f"[bold yellow]⚠[/bold yellow] {message}")
