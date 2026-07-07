"""Configuration management for Council of Experts."""

from __future__ import annotations

import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

if sys.version_info >= (3, 11):
    import tomllib
else:
    import tomli as tomllib


DEFAULT_CONFIG_PATH = Path.home() / ".config" / "council-of-experts" / "config.toml"


@dataclass
class ExpertConfig:
    """Configuration for a single expert."""

    enabled: bool = True
    model: str = ""
    # Models tried in order when the primary model fails; recorded, never silent.
    fallback_models: list[str] = field(default_factory=list)
    timeout: int = 300
    extra: dict[str, Any] = field(default_factory=dict)


@dataclass
class Config:
    """Main configuration for the council."""

    # "arbiter" (default): an LLM arbiter reconciles expert outputs and documents
    # every disagreement it resolved. "merge": programmatic deep-diff merge with
    # majority/tiebreaker resolution.
    consensus: str = "arbiter"
    arbiter_order: list[str] = field(default_factory=lambda: ["codex", "claude"])
    reconciliation_rounds: int = 2
    tiebreaker_expert: str = "claude"
    debate_timeout: int = 600
    experts: dict[str, ExpertConfig] = field(default_factory=dict)
    output_dir: Path = field(default_factory=lambda: Path.cwd() / "council-output")

    @classmethod
    def load(cls, path: Path | None = None) -> Config:
        """Load configuration from TOML file."""
        config_path = path or DEFAULT_CONFIG_PATH

        if not config_path.exists():
            return cls._default_config()

        with open(config_path, "rb") as f:
            data = tomllib.load(f)

        return cls._from_dict(data)

    @classmethod
    def _default_config(cls) -> Config:
        """Return default configuration."""
        # Empty model = each CLI/account's default model; hardcoding model ids
        # breaks when the account or CLI stops supporting them.
        return cls(
            experts={
                "claude": ExpertConfig(enabled=True, model=""),
                "codex": ExpertConfig(enabled=True, model=""),
            }
        )

    @classmethod
    def _from_dict(cls, data: dict[str, Any]) -> Config:
        """Create config from dictionary."""
        experts = {}
        for name, expert_data in data.get("experts", {}).items():
            if isinstance(expert_data, dict):
                experts[name] = ExpertConfig(
                    enabled=expert_data.get("enabled", True),
                    model=expert_data.get("model", ""),
                    fallback_models=list(expert_data.get("fallback_models", [])),
                    timeout=expert_data.get("timeout", 300),
                    extra={
                        k: v
                        for k, v in expert_data.items()
                        if k not in ("enabled", "model", "fallback_models", "timeout")
                    },
                )

        output_dir = data.get("output_dir")
        if output_dir:
            output_dir = Path(output_dir)
        else:
            output_dir = Path.cwd() / "council-output"

        return cls(
            consensus=data.get("consensus", "arbiter"),
            arbiter_order=list(data.get("arbiter_order", ["codex", "claude"])),
            reconciliation_rounds=data.get("reconciliation_rounds", 2),
            tiebreaker_expert=data.get("tiebreaker_expert", "claude"),
            debate_timeout=data.get("debate_timeout", 600),
            experts=experts or cls._default_config().experts,
            output_dir=output_dir,
        )

    def to_toml(self) -> str:
        """Serialize config to TOML string."""
        arbiter_order = ", ".join(f'"{n}"' for n in self.arbiter_order)
        lines = [
            f'consensus = "{self.consensus}"',
            f"arbiter_order = [{arbiter_order}]",
            f"reconciliation_rounds = {self.reconciliation_rounds}",
            f'tiebreaker_expert = "{self.tiebreaker_expert}"',
            f"debate_timeout = {self.debate_timeout}",
            "",
        ]

        for name, expert in self.experts.items():
            lines.append(f"[experts.{name}]")
            lines.append(f"enabled = {str(expert.enabled).lower()}")
            if expert.model:
                lines.append(f'model = "{expert.model}"')
            if expert.fallback_models:
                fallbacks = ", ".join(f'"{m}"' for m in expert.fallback_models)
                lines.append(f"fallback_models = [{fallbacks}]")
            lines.append(f"timeout = {expert.timeout}")
            for k, v in expert.extra.items():
                if isinstance(v, str):
                    lines.append(f'{k} = "{v}"')
                else:
                    lines.append(f"{k} = {v}")
            lines.append("")

        return "\n".join(lines)

    def save(self, path: Path | None = None) -> None:
        """Save configuration to TOML file."""
        config_path = path or DEFAULT_CONFIG_PATH
        config_path.parent.mkdir(parents=True, exist_ok=True)
        config_path.write_text(self.to_toml())
