"""Main council orchestrator."""

from __future__ import annotations

import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import urlparse

from council_of_experts.config import Config
from council_of_experts.consensus import run_council
from council_of_experts.debate import DebateProtocol
from council_of_experts.experts.registry import ExpertRegistry
from council_of_experts.schemas import CouncilResult, GuidanceOutput

if TYPE_CHECKING:
    from council_of_experts.experts.base import Expert


@dataclass
class PRData:
    """Data for a pull request."""

    repo: str
    number: int
    title: str = ""
    diff: str = ""
    description: str = ""  # PR body contains SAST finding details


def parse_repo_arg(repo_arg: str) -> str:
    """Parse a repo argument into owner/repo format.

    Accepts:
        - Full URL: https://github.com/owner/repo
        - owner/repo format
        - Just repo name (assumes AppSecureAI owner)

    Returns:
        owner/repo string
    """
    if repo_arg.startswith("https://") or repo_arg.startswith("http://"):
        parsed = urlparse(repo_arg)
        path = parsed.path.strip("/")
        path = re.sub(r"\.git$", "", path)
        parts = path.split("/")
        if len(parts) >= 2:
            return f"{parts[0]}/{parts[1]}"
        raise ValueError(f"Invalid GitHub URL: {repo_arg}")

    if "/" in repo_arg:
        return repo_arg

    return f"AppSecureAI/{repo_arg}"


class Council:
    """Main orchestrator for the council of experts."""

    def __init__(self, config: Config | None = None):
        """Initialize council with configuration."""
        self.config = config or Config.load()
        self._ensure_experts_loaded()

    def _ensure_experts_loaded(self) -> None:
        """Ensure expert modules are imported for registration."""
        from council_of_experts.experts import claude, codex  # noqa: F401

    def get_available_experts(self) -> list[tuple[str, bool, str]]:
        """Get list of experts with availability status.

        Returns list of (name, is_available, model).
        """
        result = []
        for name in ExpertRegistry.list_experts():
            expert_config = self.config.experts.get(name)
            if expert_config and not expert_config.enabled:
                continue

            model = expert_config.model if expert_config else ""
            expert = ExpertRegistry.create(name, model=model)
            if expert:
                result.append((name, expert.is_available(), model))

        return result

    def create_experts(self, names: list[str] | None = None) -> list[Expert]:
        """Create expert instances.

        Args:
            names: List of expert names to create. If None, uses all enabled experts.
        """
        experts = []

        if names is None:
            names = [
                name for name, cfg in self.config.experts.items()
                if cfg.enabled
            ]

        for name in names:
            expert_config = self.config.experts.get(name)
            model = expert_config.model if expert_config else None
            timeout = expert_config.timeout if expert_config else 300
            fallbacks = expert_config.fallback_models if expert_config else None

            expert = ExpertRegistry.create(
                name, model=model, timeout=timeout, fallback_models=fallbacks
            )
            if expert and expert.is_available():
                experts.append(expert)

        return experts

    def fetch_pr_data(self, repo: str, pr_numbers: list[int]) -> list[PRData]:
        """Fetch PR data using gh CLI.

        Args:
            repo: Repository in owner/repo format or URL.
            pr_numbers: List of PR numbers to fetch.
        """
        full_repo = parse_repo_arg(repo)
        pr_data_list = []

        for pr_num in pr_numbers:
            try:
                # Fetch title and body (description contains SAST finding details)
                pr_result = subprocess.run(
                    ["gh", "pr", "view", str(pr_num), "--repo", full_repo,
                     "--json", "title,body"],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                pr_info = json.loads(pr_result.stdout)
                title = pr_info.get("title", "")
                description = pr_info.get("body", "")

                diff_result = subprocess.run(
                    ["gh", "pr", "diff", str(pr_num), "--repo", full_repo],
                    capture_output=True,
                    text=True,
                    check=True,
                )
                diff = diff_result.stdout

                pr_data_list.append(PRData(
                    repo=full_repo,
                    number=pr_num,
                    title=title,
                    diff=diff[:10000],
                    description=description,
                ))
            except subprocess.CalledProcessError as e:
                raise RuntimeError(f"Failed to fetch PR {pr_num} from {full_repo}: {e.stderr}")

        return pr_data_list

    def fetch_open_prs(self, repo: str) -> list[int]:
        """Fetch open PR numbers created by AppSecAI bots.

        Only fetches PRs from:
        - appsecai-app[bot]
        - appsecai-inte-tool[bot]

        Args:
            repo: Repository in owner/repo format or URL.
        """
        full_repo = parse_repo_arg(repo)
        bot_authors = {"appsecai-app[bot]", "appsecai-inte-tool[bot]"}

        try:
            result = subprocess.run(
                ["gh", "pr", "list", "--repo", full_repo,
                 "--state", "open", "--json", "number,author",
                 "--limit", "100"],
                capture_output=True,
                text=True,
                check=True,
            )
            prs = json.loads(result.stdout) if result.stdout.strip() else []

            # Filter to only bot-created PRs
            numbers = [
                pr["number"]
                for pr in prs
                if pr.get("author", {}).get("login") in bot_authors
            ]
            return numbers
        except subprocess.CalledProcessError as e:
            raise RuntimeError(f"Failed to fetch open PRs from {full_repo}: {e.stderr}")

    async def generate(
        self,
        prs: list[PRData],
        expert_names: list[str] | None = None,
        reconciliation_rounds: int | None = None,
        tiebreaker: str | None = None,
        existing_guidelines: str | None = None,
    ) -> CouncilResult:
        """Generate security guidance from the council.

        Args:
            prs: List of PR data to analyze.
            expert_names: Experts to use (default: all enabled).
            reconciliation_rounds: Override config reconciliation rounds.
            tiebreaker: Override config tiebreaker expert.
            existing_guidelines: Current guidelines for context.
        """
        experts = self.create_experts(expert_names)
        if not experts:
            raise RuntimeError("No available experts")

        pr_dicts = [
            {
                "repo": pr.repo,
                "number": pr.number,
                "title": pr.title,
                "diff": pr.diff,
                "description": pr.description,
            }
            for pr in prs
        ]

        prompt = experts[0].build_prompt(pr_dicts, existing_guidelines)

        protocol = DebateProtocol(
            experts=experts,
            tiebreaker_expert=tiebreaker or self.config.tiebreaker_expert,
            max_reconciliation_rounds=(
                reconciliation_rounds
                if reconciliation_rounds is not None
                else self.config.reconciliation_rounds
            ),
            timeout=self.config.debate_timeout,
        )

        return await protocol.run(prompt)

    def generate_arbiter(
        self,
        prs: list[PRData],
        expert_names: list[str] | None = None,
        arbiter_order: list[str] | None = None,
        existing_guidelines: str | None = None,
        log_dir: Path | None = None,
    ) -> tuple[dict | None, dict, GuidanceOutput | None]:
        """Generate guidance via arbiter consensus (the default strategy).

        Every expert answers independently, then an LLM arbiter reconciles the
        answers into one consensus and documents each disagreement it resolved.

        Returns ``(merged, status, guidance)`` — the raw consensus dict (with
        ``consensus``/``disagreements``/``council``/``arbiter`` keys), the
        degradation status, and the consensus validated as GuidanceOutput
        (None if validation failed or all experts failed).
        """
        experts = self.create_experts(expert_names)
        if not experts:
            raise RuntimeError("No available experts")

        pr_dicts = [
            {
                "repo": pr.repo,
                "number": pr.number,
                "title": pr.title,
                "diff": pr.diff,
                "description": pr.description,
            }
            for pr in prs
        ]

        base_prompt = experts[0].build_prompt(pr_dicts, existing_guidelines)
        prompt = experts[0].build_schema_prompt(base_prompt)

        merged, status = run_council(
            prompt,
            experts=experts,
            arbiter_order=arbiter_order or self.config.arbiter_order,
            log_dir=log_dir,
        )

        guidance = None
        if merged is not None:
            try:
                guidance = GuidanceOutput.model_validate(merged.get("consensus") or {})
            except Exception:  # noqa: BLE001 - raw consensus is still returned for the caller
                guidance = None
        return merged, status, guidance

    def save_result(
        self, result: CouncilResult | dict, output_dir: Path | None = None
    ) -> Path:
        """Save council result to output directory.

        Returns path to the saved file.
        """
        out_dir = output_dir or self.config.output_dir
        out_dir.mkdir(parents=True, exist_ok=True)

        from datetime import datetime
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        output_file = out_dir / f"council_result_{timestamp}.json"

        data = result.model_dump() if isinstance(result, CouncilResult) else result
        output_file.write_text(json.dumps(data, indent=2, default=str))

        return output_file
