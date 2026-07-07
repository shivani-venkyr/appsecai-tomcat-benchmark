"""Claude Code CLI expert adapter."""

from __future__ import annotations

import asyncio
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

from council_of_experts.experts.base import Expert
from council_of_experts.experts.registry import register_expert

if TYPE_CHECKING:
    from council_of_experts.schemas import ExpertResponse


@register_expert("claude")
class ClaudeExpert(Expert):
    """Expert adapter for Claude Code CLI."""

    name = "claude"
    description = "Claude Code CLI (Anthropic)"

    @property
    def default_model(self) -> str:
        # Empty = the claude CLI's configured default model; hardcoding a model
        # id breaks when the account/CLI no longer supports it.
        return ""

    def is_available(self) -> bool:
        """Check if claude CLI is available."""
        return shutil.which("claude") is not None

    def _complete_once(self, prompt: str, model: str) -> str:
        """One completion via ``claude -p`` (prompt on stdin)."""
        cmd = ["claude", "--bare", "-p"]
        if model:
            cmd += ["--model", model]
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=self.timeout,
        )
        if proc.returncode != 0:
            raise RuntimeError(
                f"claude -p failed rc={proc.returncode}: {proc.stderr[:300]}"
            )
        return proc.stdout.strip()

    async def generate(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> ExpertResponse:
        """Generate schema-validated output using the claude CLI."""
        from council_of_experts.schemas import ExpertResponse

        start_time = time.time()
        full_prompt = self.build_schema_prompt(prompt, schema)
        raw_output = await asyncio.to_thread(self.complete, full_prompt)
        generation_time = time.time() - start_time

        guidance = self.parse_json_response(raw_output)

        return ExpertResponse(
            expert_name=self.name,
            model=self.model_used or self.model,
            guidance=guidance,
            generation_time=generation_time,
            raw_output=raw_output,
        )
