"""Expert adapters for AI models."""

from council_of_experts.experts.base import Expert
from council_of_experts.experts.registry import ExpertRegistry, register_expert

__all__ = ["Expert", "ExpertRegistry", "register_expert"]
