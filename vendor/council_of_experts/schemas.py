"""Pydantic models for structured output from experts."""

from __future__ import annotations

from enum import Enum
from typing import Any

from pydantic import BaseModel, Field


class TriageVerdict(str, Enum):
    """Verdict on whether Product's triage was correct."""
    CORRECT = "correct"
    INCORRECT = "incorrect"
    NEEDS_REVIEW = "needs_review"


class FixVerdict(str, Enum):
    """Verdict on whether Product's fix is complete."""
    COMPLETE = "complete"
    INCOMPLETE = "incomplete"
    INEFFECTIVE = "ineffective"


class Severity(str, Enum):
    """Vulnerability severity."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


class TriageEvaluation(BaseModel):
    """Evaluation of Product's triage decision."""

    original_finding_cwe: str = Field(..., description="CWE from the SAST finding")
    product_classified_as_tp: bool = Field(..., description="Did Product classify this as TP?")
    triage_verdict: TriageVerdict = Field(..., description="Was Product's triage correct?")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this evaluation")
    reasoning: str = Field(..., description="Why the triage was correct/incorrect")
    evidence: list[str] = Field(default_factory=list, description="Code evidence supporting verdict")

    # If triage was wrong, what should it have been?
    should_have_been_tp: bool | None = Field(None, description="If incorrect, what was the right call?")
    missed_context: str | None = Field(None, description="Context Product should have considered")


class FixEvaluation(BaseModel):
    """Evaluation of Product's remediation."""

    fix_verdict: FixVerdict = Field(..., description="Is the fix complete?")
    confidence: float = Field(..., ge=0.0, le=1.0, description="Confidence in this evaluation")
    reasoning: str = Field(..., description="Why the fix is complete/incomplete/ineffective")

    # What's good about the fix
    correct_patterns: list[str] = Field(default_factory=list, description="Security patterns correctly applied")

    # What's missing or wrong
    gaps: list[str] = Field(default_factory=list, description="Gaps or issues in the fix")
    recommendations: list[str] = Field(default_factory=list, description="How to improve the fix")


class PREvaluation(BaseModel):
    """Complete evaluation of a single remediation PR."""

    pr_number: int = Field(..., description="Pull request number")
    repo: str = Field(..., description="Repository name")
    cwe: str = Field(..., description="Primary CWE being addressed")

    # Evaluation of Product's work
    triage_evaluation: TriageEvaluation = Field(..., description="Was the triage correct?")
    fix_evaluation: FixEvaluation = Field(..., description="Is the fix complete?")

    # Summary
    summary: str = Field(..., description="Overall assessment")


class TriageGuidelineUpdate(BaseModel):
    """Proposed update to triage guidelines."""

    cwe: str = Field(..., description="CWE this applies to")
    language: str = Field(..., description="Language (python, csharp, java, etc.)")
    framework_family: str | None = Field(None, description="Framework family if applicable")

    update_type: str = Field(..., description="add_rule/modify_rule/add_context")

    # The actual update content matching Product's guideline format
    content: dict[str, Any] = Field(..., description="Content in Product's guideline format")

    rationale: str = Field(..., description="Why this update improves triage")
    based_on_prs: list[int] = Field(default_factory=list, description="PRs that informed this")


class RemediationGuidelineUpdate(BaseModel):
    """Proposed update to remediation guidelines."""

    cwe: str = Field(..., description="CWE this applies to")
    language: str = Field(..., description="Language (python, csharp, java, etc.)")
    framework_family: str | None = Field(None, description="Framework family if applicable")

    update_type: str = Field(..., description="add_pattern/modify_pattern/add_example")

    # The actual update content matching Product's guideline format
    content: dict[str, Any] = Field(..., description="Content in Product's guideline format")

    rationale: str = Field(..., description="Why this update improves remediation")
    based_on_prs: list[int] = Field(default_factory=list, description="PRs that informed this")


class GuidanceOutput(BaseModel):
    """Complete evaluation output from an expert."""

    # Evaluation of each PR
    pr_evaluations: list[PREvaluation] = Field(
        default_factory=list, description="Evaluation of each remediation PR"
    )

    # Summary statistics
    triage_accuracy: float = Field(
        0.0, ge=0.0, le=1.0, description="Percentage of correct triage decisions"
    )
    fix_completeness: float = Field(
        0.0, ge=0.0, le=1.0, description="Percentage of complete fixes"
    )

    # Actionable updates for Product's guidelines
    triage_guideline_updates: list[TriageGuidelineUpdate] = Field(
        default_factory=list, description="Updates to improve future triage"
    )
    remediation_guideline_updates: list[RemediationGuidelineUpdate] = Field(
        default_factory=list, description="Updates to improve future fixes"
    )

    # Patterns learned
    lessons_learned: list[str] = Field(
        default_factory=list, description="Key insights from this evaluation"
    )


class ExpertResponse(BaseModel):
    """Response from a single expert."""

    expert_name: str = Field(..., description="Name of the expert")
    model: str = Field(..., description="Model used")
    guidance: GuidanceOutput = Field(..., description="The evaluation output")
    generation_time: float = Field(..., description="Time taken in seconds")
    raw_output: str | None = Field(None, description="Raw output for debugging")


class ConflictResolution(BaseModel):
    """Record of how a conflict was resolved."""

    field_path: str = Field(..., description="JSON path to the conflicting field")
    expert_values: dict[str, Any] = Field(..., description="Value from each expert")
    resolved_value: Any = Field(..., description="Final resolved value")
    resolution_method: str = Field(..., description="majority/tiebreaker/unanimous/manual")
    tiebreaker_expert: str | None = Field(None, description="Expert that broke tie if applicable")


class CouncilResult(BaseModel):
    """Final result from the council of experts."""

    guidance: GuidanceOutput = Field(..., description="Merged evaluation output")
    agreement_score: float = Field(..., ge=0.0, le=1.0, description="Overall agreement between experts")
    conflicts_resolved: int = Field(0, description="Number of conflicts resolved automatically")
    conflicts_manual: int = Field(0, description="Number of conflicts requiring manual review")
    expert_contributions: dict[str, float] = Field(
        default_factory=dict, description="Contribution weight of each expert"
    )
    audit_trail: list[ConflictResolution] = Field(
        default_factory=list, description="How each conflict was resolved"
    )
    expert_responses: list[ExpertResponse] = Field(
        default_factory=list, description="Raw responses from each expert"
    )
    reconciliation_rounds: int = Field(0, description="Number of reconciliation rounds run")
