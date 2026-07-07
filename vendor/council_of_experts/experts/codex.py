"""Codex CLI expert adapter."""

from __future__ import annotations

import asyncio
import json
import shutil
import subprocess
import time
from typing import TYPE_CHECKING

from council_of_experts.experts.base import Expert
from council_of_experts.experts.registry import register_expert

if TYPE_CHECKING:
    from council_of_experts.schemas import ExpertResponse


@register_expert("codex")
class CodexExpert(Expert):
    """Expert adapter for Codex CLI."""

    name = "codex"
    description = "Codex CLI (OpenAI)"

    @property
    def default_model(self) -> str:
        # Empty = the codex account's default model; hardcoding a model id
        # breaks when the account/CLI no longer supports it.
        return ""

    def is_available(self) -> bool:
        """Check if codex CLI is available."""
        return shutil.which("codex") is not None

    def _complete_once(self, prompt: str, model: str) -> str:
        """One completion via ``codex exec`` (non-interactive, read-only sandbox).

        ``codex exec --json`` streams NDJSON events on stdout; the answer is the
        last ``agent_message`` item. Failures are reported as error/turn.failed
        events on stdout — stderr is often empty.
        """
        cmd = ["codex", "exec", "--skip-git-repo-check", "--json", "-s", "read-only"]
        if model:
            cmd += ["--model", model]
        cmd += ["-"]  # read the prompt from stdin
        proc = subprocess.run(
            cmd, input=prompt, capture_output=True, text=True, timeout=self.timeout,
        )
        if proc.returncode != 0:
            error_msg = proc.stderr.strip() or self._extract_error(proc.stdout)
            raise RuntimeError(f"codex exec failed rc={proc.returncode}: {error_msg}")
        return self._extract_agent_message(proc.stdout)

    async def generate(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> ExpertResponse:
        """Generate schema-validated output using the codex CLI."""
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

    @staticmethod
    def _extract_agent_message(ndjson: str) -> str:
        text = None
        for line in ndjson.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = obj.get("item") or {}
            if obj.get("type") == "item.completed" and item.get("type") == "agent_message":
                text = item.get("text")
        if not text:
            raise ValueError("codex: no agent_message in output")
        return text

    @staticmethod
    def _extract_error(ndjson: str) -> str:
        msgs = []
        for line in ndjson.splitlines():
            try:
                obj = json.loads(line)
            except json.JSONDecodeError:
                continue
            item = obj.get("item") or {}
            if obj.get("type") == "error" and obj.get("message"):
                msgs.append(obj["message"])
            elif obj.get("type") == "turn.failed":
                msgs.append((obj.get("error") or {}).get("message", "turn.failed"))
            elif item.get("type") == "error" and item.get("message"):
                msgs.append(item["message"])
        return "; ".join(msgs)[:500] or "no error detail in output"
