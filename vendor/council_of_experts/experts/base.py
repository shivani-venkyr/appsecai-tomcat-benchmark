"""Abstract base class for expert adapters."""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from council_of_experts.schemas import ExpertResponse, GuidanceOutput


class Expert(ABC):
    """Abstract base class for AI expert adapters.

    ``complete()`` is the primitive every adapter must provide: raw prompt in,
    raw text out, synchronous, stdlib-only. The arbiter consensus path
    (``council_of_experts.consensus``) uses only ``complete()``, so operational
    scripts can drive experts without the package's CLI dependencies installed.

    ``generate()`` layers schema-forced JSON generation on top for the
    merge-based debate protocol.
    """

    name: str = "base"
    description: str = "Base expert class"

    def __init__(
        self,
        model: str | None = None,
        timeout: int = 300,
        fallback_models: list[str] | None = None,
    ):
        """Initialize expert with optional model override, timeout, and fallbacks.

        ``fallback_models`` are tried in order when the primary model fails
        (error or timeout). Which model actually answered is recorded in
        ``model_used`` — a fallback is never silent.
        """
        self.model = model if model is not None else self.default_model
        self.timeout = timeout
        self.fallback_models = list(fallback_models or [])
        self.model_used: str | None = None

    @property
    @abstractmethod
    def default_model(self) -> str:
        """Return the default model for this expert ("" = CLI/account default)."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if this expert is available (CLI installed, API key set, etc.)."""
        ...

    @abstractmethod
    def _complete_once(self, prompt: str, model: str) -> str:
        """Single completion attempt against one specific model ("" = default)."""
        ...

    def complete(self, prompt: str) -> str:
        """Raw text completion: prompt in, response text out (synchronous).

        Tries the configured model, then each entry of ``fallback_models`` in
        order. Sets ``model_used`` to the model that answered; raises with the
        per-model errors if every model failed.
        """
        models = [self.model]
        models += [m for m in self.fallback_models if m not in models]
        errors: list[str] = []
        for model in models:
            try:
                out = self._complete_once(prompt, model)
                self.model_used = model
                return out
            except Exception as exc:  # noqa: BLE001 - each model gets its shot; errors are re-raised below
                errors.append(f"{model or '(default)'}: {str(exc)[:200]}")
        raise RuntimeError(f"{self.name}: all models failed: " + " | ".join(errors))

    @abstractmethod
    async def generate(
        self,
        prompt: str,
        schema: dict | None = None,
    ) -> ExpertResponse:
        """Generate schema-validated guidance from the expert."""
        ...

    def get_schema_json(self) -> str:
        """Get the JSON schema for GuidanceOutput."""
        from council_of_experts.schemas import GuidanceOutput
        return json.dumps(GuidanceOutput.model_json_schema(), indent=2)

    def build_schema_prompt(self, prompt: str, schema: dict | None = None) -> str:
        """Wrap a prompt with strict JSON-schema output instructions."""
        schema_json = schema or json.loads(self.get_schema_json())
        return f"""{prompt}

IMPORTANT: You MUST respond with ONLY valid JSON matching this exact schema:

```json
{json.dumps(schema_json, indent=2)}
```

Your response must be valid JSON only - no markdown, no explanation, just the JSON object.
Start your response with {{ and end with }}."""

    def parse_json_response(self, raw_output: str) -> GuidanceOutput:
        """Extract and parse a GuidanceOutput JSON object from response text."""
        from council_of_experts.schemas import GuidanceOutput

        json_match = re.search(r"\{[\s\S]*\}", raw_output)
        if not json_match:
            raise ValueError(f"No JSON found in output: {raw_output[:500]}")

        try:
            output_data = json.loads(json_match.group(0))
            return GuidanceOutput.model_validate(output_data)
        except json.JSONDecodeError as e:
            fenced = re.search(r"```(?:json)?\s*(\{[\s\S]*?\})\s*```", raw_output)
            if fenced:
                try:
                    output_data = json.loads(fenced.group(1))
                    return GuidanceOutput.model_validate(output_data)
                except (json.JSONDecodeError, ValueError):
                    pass
            raise ValueError(f"Failed to parse JSON: {e}\nRaw: {raw_output[:500]}")

    def build_prompt(
        self,
        prs: list[dict],
        existing_guidelines: str | None = None,
    ) -> str:
        """Build the prompt for evaluating triage and remediation work.

        Args:
            prs: List of PR data dictionaries with number, repo, diff, etc.
            existing_guidelines: Current guidelines content for context.

        Returns:
            Formatted prompt string.
        """
        pr_sections = []
        for pr in prs:
            pr_sections.append(
                f"## PR #{pr['number']} in {pr['repo']}\n\n"
                f"**Title:** {pr.get('title', 'N/A')}\n\n"
                f"**Description (contains SAST finding details):**\n{pr.get('description', 'N/A')}\n\n"
                f"**Diff (- is original vulnerable code, + is the fix):**\n```diff\n{pr.get('diff', '')}\n```\n"
            )

        pr_content = "\n---\n".join(pr_sections)

        guidelines_section = ""
        if existing_guidelines:
            guidelines_section = f"""
## Current Security Guidelines (IMPORTANT - Review Before Recommending Updates)

Product already has these guidelines. Before recommending any updates:
1. Check if the pattern/rule already exists
2. Only recommend NEW rules or MODIFICATIONS to existing rules
3. Reference existing rules by name when suggesting modifications
4. Avoid duplicating existing guidance

{existing_guidelines}

"""

        return f"""You are evaluating the quality of Product's security triage and remediation work.

## Context

Product is a security platform that:
1. Ingests SAST (Static Application Security Testing) findings
2. Triages each finding as TRUE POSITIVE (real vulnerability) or FALSE POSITIVE
3. For TRUE POSITIVEs, generates code fixes (remediation PRs)

You are reviewing remediation PRs. Each PR contains:
- The SAST finding details in the PR description (CWE, location, why it was flagged)
- The diff showing the ORIGINAL vulnerable code (- lines) and the FIX (+ lines)

## Your Task

For each PR, evaluate TWO things:

### 1. TRIAGE EVALUATION
Was Product correct to classify the original code as a TRUE POSITIVE?
- Look at the ORIGINAL code (the - lines in the diff)
- Consider the SAST finding details in the PR description
- Was this actually exploitable? Was it a real vulnerability?

### 2. FIX EVALUATION
Is Product's fix complete and effective?
- Does it fully address the root cause?
- Are there any gaps, edge cases, or bypasses?
- Does it follow security best practices for this vulnerability type?

## Output Requirements

Provide:
1. **pr_evaluations**: Assessment of each PR's triage correctness and fix quality
2. **triage_accuracy**: Overall percentage of correct triage decisions
3. **fix_completeness**: Overall percentage of complete/effective fixes
4. **triage_guideline_updates**: Specific updates to improve future triage (in Product's guideline format)
5. **remediation_guideline_updates**: Specific updates to improve future fixes (in Product's guideline format)
6. **lessons_learned**: Key insights from this evaluation batch

{guidelines_section}

# Remediation PRs to Evaluate

{pr_content}

Respond with structured JSON matching the GuidanceOutput schema.

Focus on:
- Validating triage decisions with concrete evidence
- Identifying incomplete or bypassable fixes
- Generating actionable guideline updates that will improve future work"""
