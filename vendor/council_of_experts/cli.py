"""Click CLI for Council of Experts."""

from __future__ import annotations

import asyncio
import json
import os
import sys
from pathlib import Path

import click

from council_of_experts.config import DEFAULT_CONFIG_PATH, Config
from council_of_experts.consensus import run_council
from council_of_experts.council import Council, parse_repo_arg
from council_of_experts.output import (
    console,
    print_arbiter_result,
    print_ask_result,
    print_audit_tree,
    print_council_result,
    print_error,
    print_experts_table,
    print_header,
    print_success,
    print_warning,
)

# Known locations for guideline files. Override with COUNCIL_GUIDELINES_DIR.
GUIDELINE_SEARCH_PATHS = [
    Path.cwd() / "Product" / "data" / "guidelines",
    Path.cwd() / "data" / "guidelines",
]

GUIDELINE_FILES = [
    "csharp_triage_guidelines.json",
    "csharp_remediation_guidelines.json",
    "python_triage_guidelines.json",
    "python_remediation_guidelines.json",
    "java_triage_guidelines.json",
    "java_remediation_guidelines.json",
]

# Default answer shape for `council ask` (document mode).
DEFAULT_ASK_SHAPE = {
    "answer": "<your full answer; markdown allowed>",
    "key_points": ["<key point>"],
    "confidence": "high|medium|low",
}


def _load_product_guidelines() -> str | None:
    """Auto-load existing guideline files.

    Returns concatenated content of all found guideline files,
    or None if no guidelines found.
    """
    guidelines_content = []

    search_paths = list(GUIDELINE_SEARCH_PATHS)
    env_dir = os.environ.get("COUNCIL_GUIDELINES_DIR")
    if env_dir:
        search_paths.insert(0, Path(env_dir))

    for base_path in search_paths:
        if not base_path.exists():
            continue

        for filename in GUIDELINE_FILES:
            filepath = base_path / filename
            if filepath.exists():
                try:
                    content = filepath.read_text()
                    guidelines_content.append(f"### {filename}\n\n```json\n{content}\n```")
                except OSError:
                    pass

        # If we found guidelines in this path, don't check others
        if guidelines_content:
            break

    if guidelines_content:
        return "\n\n".join(guidelines_content)
    return None


def _select_experts(council: Council, expert: tuple[str, ...]) -> list[str] | None:
    """Validate -e/--expert selections against availability; exit on error."""
    available = council.get_available_experts()
    selected = list(expert) if expert else None

    if selected:
        unavailable = [
            e for e in selected
            if e not in [name for name, avail, _ in available if avail]
        ]
        if unavailable:
            print_error(f"Experts not available: {', '.join(unavailable)}")
            sys.exit(1)

    if not any(avail for _, avail, _ in available):
        print_error("No experts available. Install claude or codex CLI.")
        sys.exit(1)

    return selected


@click.group()
@click.version_option()
def cli():
    """Council of Experts - Multi-model AI consensus."""
    pass


@cli.command()
@click.argument("question")
@click.option(
    "-e", "--expert",
    multiple=True,
    help="Expert to use (can specify multiple). Default: all enabled.",
)
@click.option(
    "--arbiter",
    multiple=True,
    help="Arbiter fallback order (expert names). Default: config arbiter_order.",
)
@click.option(
    "--schema",
    type=click.Path(exists=True, path_type=Path),
    help="JSON file describing the answer shape experts must return.",
)
@click.option(
    "--list-key",
    default=None,
    help="Merge expert outputs as lists under this key instead of whole documents.",
)
@click.option(
    "--log-dir",
    type=click.Path(path_type=Path),
    help="Persist the full audit trail (prompt, responses, arbiter I/O, status).",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    help="Output directory for the consensus JSON.",
)
@click.option(
    "--json", "json_out",
    is_flag=True,
    help="Print the raw consensus JSON instead of formatted output.",
)
def ask(
    question: str,
    expert: tuple[str, ...],
    arbiter: tuple[str, ...],
    schema: Path | None,
    list_key: str | None,
    log_dir: Path | None,
    output: Path | None,
    json_out: bool,
):
    """Ask the council a question and get an arbiter-reconciled consensus answer.

    \b
    Examples:
        council ask "Should we pin dependencies exactly or use ranges?"
        council ask "Review this design: ..." -e claude -e codex
        council ask "List risks of enabling CORS *" --list-key risks
    """
    if not json_out:
        print_header("Council of Experts")

    try:
        council = Council()
        selected = _select_experts(council, expert)
        experts = council.create_experts(selected)

        if schema:
            shape = json.loads(schema.read_text())
        elif list_key:
            shape = {list_key: [{"point": "<the point>", "detail": "<explanation>",
                                 "severity": "low|medium|high"}]}
        else:
            shape = DEFAULT_ASK_SHAPE

        prompt = (
            f"{question}\n\n"
            f"Return STRICT JSON only (no markdown fences, no prose outside JSON) matching:\n"
            f"{json.dumps(shape, indent=2)}"
        )

        merged, status = run_council(
            prompt,
            experts=experts,
            list_key=list_key,
            arbiter_order=list(arbiter) or council.config.arbiter_order,
            log_dir=log_dir,
            log=(lambda _msg: None) if json_out else console.print,
        )

        if merged is None:
            print_error(f"All experts failed: {status['experts']}")
            sys.exit(1)

        if json_out:
            click.echo(json.dumps(merged, indent=2, default=str))
        else:
            print_ask_result(merged, status, list_key)

        if output:
            output_file = council.save_result(merged, output)
            if not json_out:
                print_success(f"Results saved to: {output_file}")

    except Exception as e:
        print_error(str(e))
        raise click.Abort()


@cli.command()
@click.argument("repo", required=False)
@click.argument("prs", required=False)
@click.option(
    "-e", "--expert",
    multiple=True,
    help="Expert to use (can specify multiple). Default: all enabled.",
)
@click.option(
    "--consensus",
    type=click.Choice(["arbiter", "merge"]),
    default=None,
    help="Consensus strategy. Default: config (arbiter).",
)
@click.option(
    "-r", "--rounds",
    type=int,
    default=None,
    help="Number of reconciliation rounds (merge mode only).",
)
@click.option(
    "-t", "--tiebreaker",
    default=None,
    help="Tiebreaker expert name (merge mode only).",
)
@click.option(
    "--log-dir",
    type=click.Path(path_type=Path),
    help="Persist the full audit trail (arbiter mode only).",
)
@click.option(
    "-o", "--output",
    type=click.Path(path_type=Path),
    help="Output directory for results.",
)
@click.option(
    "--guidelines",
    type=click.Path(exists=True, path_type=Path),
    help="Path to existing guidelines file for context.",
)
@click.option(
    "--audit",
    is_flag=True,
    help="Show detailed audit trail of conflict resolutions.",
)
def generate(
    repo: str | None,
    prs: str | None,
    expert: tuple[str, ...],
    consensus: str | None,
    rounds: int | None,
    tiebreaker: str | None,
    log_dir: Path | None,
    output: Path | None,
    guidelines: Path | None,
    audit: bool,
):
    """Generate security guidance from PRs.

    \b
    Examples:
        council generate                                        # All open PRs from default repos
        council generate https://github.com/owner/repo          # From GitHub URL
        council generate owner/repo                             # From owner/repo
        council generate owner/repo 123,456                     # Specific PRs
        council generate -e claude -e codex                     # Select experts
        council generate --consensus merge                      # Deep-diff merge instead of arbiter
    """
    print_header("Council of Experts - Generating Security Guidance")

    try:
        council = Council()
        selected_experts = _select_experts(council, expert)
        mode = consensus or council.config.consensus

        if repo:
            repos_to_process = [parse_repo_arg(repo)]
        else:
            repos_to_process = ["AppSecureAI/Product", "AppSecureAI/Hydra", "AppSecureAI/Fenix"]

        all_pr_data = []

        for r in repos_to_process:
            console.print(f"\nFetching PRs from [cyan]{r}[/cyan]...")

            if prs:
                pr_numbers = [int(p.strip()) for p in prs.split(",")]
            else:
                pr_numbers = council.fetch_open_prs(r)

            if not pr_numbers:
                print_warning(f"No open PRs found in {r}")
                continue

            console.print(f"  Found {len(pr_numbers)} PRs: {pr_numbers}")
            pr_data = council.fetch_pr_data(r, pr_numbers)
            all_pr_data.extend(pr_data)

        if not all_pr_data:
            print_warning("No PRs to analyze")
            return

        existing_guidelines = None
        if guidelines:
            existing_guidelines = guidelines.read_text()
        else:
            # Auto-load guideline files if they exist
            existing_guidelines = _load_product_guidelines()

        available = council.get_available_experts()
        experts_used = selected_experts or [
            name for name, avail, _ in available if avail
        ]
        console.print(f"\nRunning council with {len(all_pr_data)} PRs...")
        console.print(f"  Experts: {', '.join(experts_used)}  (consensus: {mode})")

        if mode == "arbiter":
            merged, status, guidance = council.generate_arbiter(
                prs=all_pr_data,
                expert_names=selected_experts,
                existing_guidelines=existing_guidelines,
                log_dir=log_dir,
            )
            if merged is None:
                print_error(f"All experts failed: {status['experts']}")
                sys.exit(1)
            print_arbiter_result(merged, status, guidance)
            output_file = council.save_result(merged, output)
        else:
            result = asyncio.run(
                council.generate(
                    prs=all_pr_data,
                    expert_names=selected_experts,
                    reconciliation_rounds=rounds,
                    tiebreaker=tiebreaker,
                    existing_guidelines=existing_guidelines,
                )
            )
            print_council_result(result)
            if audit:
                console.print()
                print_audit_tree(result)
            output_file = council.save_result(result, output)

        print_success(f"Results saved to: {output_file}")

    except Exception as e:
        print_error(str(e))
        raise click.Abort()


@cli.command()
def experts():
    """List available experts and their status."""
    print_header("Available Experts")

    council = Council()
    available = council.get_available_experts()

    if not available:
        print_warning("No experts registered")
        return

    print_experts_table(available)


@cli.command()
@click.option("--create", is_flag=True, help="Create default config if missing.")
@click.option("--path", type=click.Path(path_type=Path), help="Config file path.")
def config(create: bool, path: Path | None):
    """Show or create configuration."""
    config_path = path or DEFAULT_CONFIG_PATH

    if config_path.exists():
        console.print(f"[bold]Config file:[/bold] {config_path}")
        console.print()
        console.print(config_path.read_text())
    elif create:
        cfg = Config._default_config()
        cfg.save(config_path)
        print_success(f"Created config at: {config_path}")
        console.print()
        console.print(cfg.to_toml())
    else:
        print_warning(f"Config not found: {config_path}")
        console.print("Use --create to create a default config.")


if __name__ == "__main__":
    cli()
