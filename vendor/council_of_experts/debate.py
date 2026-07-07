"""Debate protocol for expert consensus building."""

from __future__ import annotations

import asyncio
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from council_of_experts.merge import MergeResult, MergeStrategy
from council_of_experts.schemas import (
    CouncilResult,
    ExpertResponse,
    GuidanceOutput,
)

if TYPE_CHECKING:
    from council_of_experts.experts.base import Expert


@dataclass
class DebateRound:
    """Result of a single debate round."""

    round_number: int
    responses: dict[str, ExpertResponse]
    merge_result: MergeResult
    conflicts_remaining: int


@dataclass
class DebateProtocol:
    """Orchestrates parallel generation and merge-based consensus."""

    experts: list[Expert]
    tiebreaker_expert: str = "claude"
    max_reconciliation_rounds: int = 2
    timeout: int = 600
    rounds: list[DebateRound] = field(default_factory=list)

    async def run(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> CouncilResult:
        """Run the debate protocol.

        1. All experts generate in parallel
        2. Merge outputs, identify conflicts
        3. If conflicts exist and rounds remain, show conflicts to experts and regenerate
        4. Return final merged result
        """
        round_num = 0
        current_prompt = prompt
        all_responses: list[ExpertResponse] = []

        while round_num <= self.max_reconciliation_rounds:
            responses = await self._parallel_generate(current_prompt, schema)
            all_responses.extend(responses.values())

            outputs = {name: resp.guidance for name, resp in responses.items()}

            strategy = MergeStrategy(tiebreaker_expert=self.tiebreaker_expert)
            merge_result = strategy.merge(outputs)

            debate_round = DebateRound(
                round_number=round_num,
                responses=responses,
                merge_result=merge_result,
                conflicts_remaining=len([
                    c for c in merge_result.conflicts
                    if c.resolution_method not in ("unanimous", "majority")
                ]),
            )
            self.rounds.append(debate_round)

            non_unanimous = [
                c for c in merge_result.conflicts
                if c.resolution_method != "unanimous"
            ]

            if not non_unanimous or round_num >= self.max_reconciliation_rounds:
                break

            current_prompt = self._build_reconciliation_prompt(
                prompt, merge_result, non_unanimous
            )
            round_num += 1

        final_merge = self.rounds[-1].merge_result
        guidance = GuidanceOutput.model_validate(final_merge.merged)

        expert_contributions = {}
        for resp in all_responses:
            if resp.expert_name not in expert_contributions:
                expert_contributions[resp.expert_name] = 0.0
            expert_contributions[resp.expert_name] += 1.0

        total = sum(expert_contributions.values())
        if total > 0:
            expert_contributions = {
                k: v / total for k, v in expert_contributions.items()
            }

        return CouncilResult(
            guidance=guidance,
            agreement_score=final_merge.agreement_score,
            conflicts_resolved=len([
                c for c in final_merge.conflicts
                if c.resolution_method in ("unanimous", "majority", "tiebreaker")
            ]),
            conflicts_manual=len([
                c for c in final_merge.conflicts
                if c.resolution_method not in ("unanimous", "majority", "tiebreaker")
            ]),
            expert_contributions=expert_contributions,
            audit_trail=final_merge.conflicts,
            expert_responses=all_responses,
            reconciliation_rounds=len(self.rounds) - 1,
        )

    async def _parallel_generate(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> dict[str, ExpertResponse]:
        """Run all experts in parallel."""
        async def run_expert(expert: Expert) -> tuple[str, ExpertResponse]:
            response = await expert.generate(prompt, schema)
            return expert.name, response

        tasks = [run_expert(e) for e in self.experts]

        try:
            results = await asyncio.wait_for(
                asyncio.gather(*tasks, return_exceptions=True),
                timeout=self.timeout,
            )
        except asyncio.TimeoutError:
            raise TimeoutError(f"Debate timed out after {self.timeout}s")

        responses = {}
        errors = []

        for result in results:
            if isinstance(result, Exception):
                errors.append(str(result))
            else:
                name, response = result
                responses[name] = response

        if not responses:
            raise RuntimeError(f"All experts failed: {errors}")

        return responses

    def _build_reconciliation_prompt(
        self,
        original_prompt: str,
        merge_result: MergeResult,
        conflicts: list,
    ) -> str:
        """Build a prompt for reconciliation round."""
        conflict_descriptions = []
        for c in conflicts[:10]:
            conflict_descriptions.append(
                f"- **{c.field_path}**: "
                f"Values differ: {c.expert_values}"
            )

        conflicts_text = "\n".join(conflict_descriptions)

        return f"""{original_prompt}

---

## Reconciliation Round

The council has identified the following conflicts between experts:

{conflicts_text}

Please reconsider your analysis for these specific points.
Focus on providing clear reasoning that could help reach consensus.
"""
