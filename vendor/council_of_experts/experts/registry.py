"""Expert registry for plugin management."""

from __future__ import annotations

from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from council_of_experts.experts.base import Expert


class ExpertRegistry:
    """Registry for managing expert adapters."""

    _experts: dict[str, type[Expert]] = {}

    @classmethod
    def register(cls, name: str, expert_cls: type[Expert]) -> None:
        """Register an expert class."""
        cls._experts[name] = expert_cls

    @classmethod
    def get(cls, name: str) -> type[Expert] | None:
        """Get an expert class by name."""
        return cls._experts.get(name)

    @classmethod
    def list_experts(cls) -> list[str]:
        """List all registered expert names."""
        return list(cls._experts.keys())

    @classmethod
    def get_all(cls) -> dict[str, type[Expert]]:
        """Get all registered experts."""
        return cls._experts.copy()

    @classmethod
    def create(
        cls,
        name: str,
        model: str | None = None,
        timeout: int = 300,
        fallback_models: list[str] | None = None,
    ) -> Expert | None:
        """Create an expert instance by name."""
        expert_cls = cls.get(name)
        if expert_cls is None:
            return None
        return expert_cls(model=model, timeout=timeout, fallback_models=fallback_models)


def register_expert(name: str):
    """Decorator to register an expert class."""

    def decorator(cls: type[Expert]) -> type[Expert]:
        cls.name = name
        ExpertRegistry.register(name, cls)
        return cls

    return decorator
