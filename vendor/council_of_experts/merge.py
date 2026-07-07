"""Merge algorithm for combining expert outputs."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from deepdiff import DeepDiff

from council_of_experts.schemas import (
    ConflictResolution,
    GuidanceOutput,
)


@dataclass
class MergeResult:
    """Result of merging multiple expert outputs."""

    merged: dict[str, Any]
    agreement_score: float
    conflicts: list[ConflictResolution]
    unanimous_fields: int
    total_fields: int


def deep_get(d: dict, path: str) -> Any:
    """Get a value from a nested dict using dot notation path."""
    keys = path.replace("root", "").strip("[]'").split("']['")
    keys = [k for k in keys if k]
    result = d
    for key in keys:
        if isinstance(result, dict):
            result = result.get(key)
        elif isinstance(result, list) and key.isdigit():
            result = result[int(key)]
        else:
            return None
    return result


def deep_set(d: dict, path: str, value: Any) -> None:
    """Set a value in a nested dict using dot notation path."""
    keys = path.replace("root", "").strip("[]'").split("']['")
    keys = [k for k in keys if k]
    current = d
    for key in keys[:-1]:
        if key.isdigit():
            key = int(key)
        if isinstance(current, dict):
            if key not in current:
                current[key] = {}
            current = current[key]
        elif isinstance(current, list):
            current = current[key]
    final_key = keys[-1]
    if final_key.isdigit():
        final_key = int(final_key)
    current[final_key] = value


@dataclass
class MergeStrategy:
    """Strategy for merging expert outputs."""

    tiebreaker_expert: str = "claude"
    require_unanimous_for: list[str] = field(default_factory=list)

    def merge(
        self,
        outputs: dict[str, GuidanceOutput],
        expert_weights: dict[str, float] | None = None,
    ) -> MergeResult:
        """Merge multiple expert outputs into a single result.

        Algorithm:
        1. Convert outputs to dicts
        2. Find agreements and conflicts via deep diff
        3. Unanimous values: include directly
        4. Conflicts: majority wins, else tiebreaker
        5. Calculate agreement score
        """
        if not outputs:
            raise ValueError("No outputs to merge")

        if len(outputs) == 1:
            name, output = next(iter(outputs.items()))
            return MergeResult(
                merged=output.model_dump(),
                agreement_score=1.0,
                conflicts=[],
                unanimous_fields=1,
                total_fields=1,
            )

        weights = expert_weights or {name: 1.0 for name in outputs}
        output_dicts = {name: out.model_dump() for name, out in outputs.items()}

        names = list(output_dicts.keys())
        base_name = names[0]
        base = output_dicts[base_name]

        conflicts: list[ConflictResolution] = []
        unanimous_count = 0
        total_comparisons = 0

        merged = self._deep_copy(base)

        for other_name in names[1:]:
            other = output_dicts[other_name]
            diff = DeepDiff(base, other, ignore_order=True, view="tree")

            for change_type in ["values_changed", "type_changes"]:
                if change_type in diff:
                    for item in diff[change_type]:
                        total_comparisons += 1
                        path = item.path()

                        expert_values = {
                            base_name: item.t1,
                            other_name: item.t2,
                        }
                        for extra_name in names:
                            if extra_name not in expert_values:
                                expert_values[extra_name] = deep_get(
                                    output_dicts[extra_name], path
                                )

                        resolved_value, method, tiebreaker = self._resolve_conflict(
                            expert_values, weights
                        )

                        conflicts.append(
                            ConflictResolution(
                                field_path=path,
                                expert_values=expert_values,
                                resolved_value=resolved_value,
                                resolution_method=method,
                                tiebreaker_expert=tiebreaker,
                            )
                        )

                        deep_set(merged, path, resolved_value)

            for change_type in ["dictionary_item_added", "iterable_item_added"]:
                if change_type in diff:
                    for item in diff[change_type]:
                        path = item.path()
                        deep_set(merged, path, item.t2)

        if total_comparisons > 0:
            unanimous_count = sum(
                1 for c in conflicts if c.resolution_method == "unanimous"
            )
            agreement_score = unanimous_count / total_comparisons
        else:
            agreement_score = 1.0
            unanimous_count = 1
            total_comparisons = 1

        return MergeResult(
            merged=merged,
            agreement_score=agreement_score,
            conflicts=conflicts,
            unanimous_fields=unanimous_count,
            total_fields=total_comparisons,
        )

    def _resolve_conflict(
        self,
        expert_values: dict[str, Any],
        weights: dict[str, float],
    ) -> tuple[Any, str, str | None]:
        """Resolve a conflict between expert values.

        Returns: (resolved_value, resolution_method, tiebreaker_expert)
        """
        value_counts: dict[Any, float] = {}
        value_to_experts: dict[Any, list[str]] = {}

        for expert, value in expert_values.items():
            hashable = self._make_hashable(value)
            weight = weights.get(expert, 1.0)
            value_counts[hashable] = value_counts.get(hashable, 0) + weight
            if hashable not in value_to_experts:
                value_to_experts[hashable] = []
            value_to_experts[hashable].append(expert)

        if len(value_counts) == 1:
            value = next(iter(expert_values.values()))
            return value, "unanimous", None

        total_weight = sum(weights.get(e, 1.0) for e in expert_values)
        majority_threshold = total_weight / 2

        for hashable, weight in sorted(
            value_counts.items(), key=lambda x: x[1], reverse=True
        ):
            if weight > majority_threshold:
                experts = value_to_experts[hashable]
                value = expert_values[experts[0]]
                return value, "majority", None

        if self.tiebreaker_expert in expert_values:
            value = expert_values[self.tiebreaker_expert]
            return value, "tiebreaker", self.tiebreaker_expert

        first_expert = next(iter(expert_values))
        return expert_values[first_expert], "first", None

    def _make_hashable(self, value: Any) -> Any:
        """Make a value hashable for comparison."""
        if isinstance(value, dict):
            return tuple(sorted((k, self._make_hashable(v)) for k, v in value.items()))
        if isinstance(value, list):
            return tuple(self._make_hashable(v) for v in value)
        return value

    def _deep_copy(self, d: dict) -> dict:
        """Deep copy a dictionary."""
        import copy
        return copy.deepcopy(d)
