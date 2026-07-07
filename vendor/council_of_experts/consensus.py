"""Arbiter-based consensus — the default council strategy.

Ported from the production guidance sweep (tools/dailystats/prod_guidance_sweep.py),
which ran this design nightly: every expert answers the same prompt independently,
then an LLM arbiter reconciles the answers into one consensus and documents every
disagreement it had to resolve. Degrades gracefully (a failed expert or arbiter is
recorded, never hidden) and persists a full audit trail when given a log dir.

This module is intentionally stdlib-only so operational scripts (e.g. the nightly
sweep) can import it without installing the package's CLI dependencies.

Two modes:
  * list mode (``list_key`` given): each expert returns ``{list_key: [items]}``;
    the arbiter merges the lists (the sweep's mode).
  * document mode (``list_key=None``): each expert returns an arbitrary JSON
    document; the arbiter reconciles them into one consensus document.
"""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from council_of_experts.experts.base import Expert

# Arbiter prompt (list mode): reconcile experts into a consensus list AND document
# where they disagreed.
ARBITER_LIST_PROMPT = """You are the chair of a review council. Independent expert reviewers each produced a JSON
list of `{list_key}` analysing the same data. Their outputs are below, keyed by expert name.

Merge them into ONE consensus list:
- Combine items that make the SAME point into a single item (keep the clearest wording).
- Add an `agreement` field: "both" if 2+ experts raised it, "single" if only one did.
- Add an `experts` field: the list of expert names that raised it.
- KEEP every substantive, actionable item — do NOT drop a real point just because only one expert caught it.
- DROP duplicates and non-actionable noise. Order by severity (high first), then agreement (both first).

ALSO document DISAGREEMENTS — every case where the experts did NOT agree and you, the arbiter, made the final
call: an item only one expert raised, or where experts conflicted (one flagged it, another judged it fine, or
they assigned different severity/verdict). For each, record what was disputed, each expert's position, your
ruling (kept | dropped | merged | severity-adjusted), and your rationale. Do NOT include customer code,
secrets, repo/org names, or PR URLs in the rationale — keep it generalized.

Preserve each item's existing fields. Return STRICT JSON only:
{{
  "{list_key}": [ ... consensus items ... ],
  "disagreements": [
    {{"topic": "<short description>", "positions": {{"<expert>": "<their stance>"}},
     "ruling": "kept|dropped|merged|severity-adjusted", "rationale": "<why the arbiter decided this>"}}
  ]
}}

EXPERT OUTPUTS (JSON):
"""

# Arbiter prompt (document mode): reconcile whole JSON documents.
ARBITER_DOC_PROMPT = """You are the chair of a review council. Independent expert reviewers each produced a JSON
document answering the same prompt. Their outputs are below, keyed by expert name.

Reconcile them into ONE consensus document with the SAME structure the experts used:
- Where experts agree, keep the shared answer (clearest wording).
- Where they conflict, make the final call and keep the best-supported answer.
- KEEP every substantive point — do NOT drop a real point just because only one expert made it.

ALSO document DISAGREEMENTS — every case where the experts did NOT agree and you, the arbiter, made the
final call. For each, record what was disputed, each expert's position, your ruling
(kept | dropped | merged | adjusted), and your rationale.

Return STRICT JSON only:
{
  "consensus": { ... consensus document ... },
  "disagreements": [
    {"topic": "<short description>", "positions": {"<expert>": "<their stance>"},
     "ruling": "kept|dropped|merged|adjusted", "rationale": "<why the arbiter decided this>"}
  ]
}

EXPERT OUTPUTS (JSON):
"""

DEFAULT_ARBITER_ORDER = ["codex", "claude"]
DEFAULT_MAX_ARBITER_CHARS = 120_000


def extract_json(text: str) -> dict:
    """Extract the first JSON object from LLM output text."""
    m = re.search(r"\{.*\}", text, re.DOTALL)
    if not m:
        raise RuntimeError(f"no JSON in output: {text[:300]}")
    return json.loads(m.group(0))


def _write(log_dir: Path | None, name: str, content: str) -> None:
    if log_dir is not None:
        (log_dir / name).write_text(content, encoding="utf-8")


def run_council(
    prompt: str,
    *,
    experts: list[Expert],
    list_key: str | None = None,
    arbiter_order: list[str] | None = None,
    log_dir: Path | str | None = None,
    pass_name: str | None = None,
    max_arbiter_chars: int = DEFAULT_MAX_ARBITER_CHARS,
    log: Callable[[str], None] = print,
) -> tuple[dict | None, dict]:
    """Run every expert on ``prompt``, then reconcile into a consensus dict.

    Returns ``(result_or_None, status)``. NEVER hides what happened:
      * every prompt, expert response, and arbiter input/output is persisted under
        ``log_dir`` (when given) for audit;
      * ``status`` records per-expert ok/failure, the arbiter used, and any
        degradation, so callers can surface it.

    Degrades gracefully (single surviving expert, arbiter fallback, programmatic
    union) rather than raising, so a scheduled caller always gets a recorded
    outcome. Only raises for caller bugs (no experts supplied).

    In list mode the consensus dict is ``{list_key: [...], "disagreements": [...]}``;
    in document mode it is ``{"consensus": {...}, "disagreements": [...]}``. Both
    carry ``council`` (expert names), ``arbiter``, and ``_experts`` (each expert's
    raw contribution) for audit.
    """
    if not experts:
        raise ValueError("run_council requires at least one expert")

    if log_dir is not None:
        log_dir = Path(log_dir)
        log_dir.mkdir(parents=True, exist_ok=True)
    _write(log_dir, "prompt.txt", prompt)

    status: dict = {"experts": {}, "arbiter": None, "degraded": False, "error": None,
                    "log_dir": str(log_dir) if log_dir else None}
    if pass_name is not None:
        status["pass"] = pass_name

    def _contribution(res: dict) -> Any:
        return (res.get(list_key) or []) if list_key else res

    # --- Parallel expert round -------------------------------------------- #
    def _ask(expert: Expert) -> tuple[Expert, dict | None, str | None]:
        try:
            raw = expert.complete(prompt)
            _write(log_dir, f"{expert.name}.response.txt", raw)
            return expert, extract_json(raw), None
        except Exception as exc:  # noqa: BLE001 - one expert failing must not kill the run
            msg = str(exc)[:300]
            _write(log_dir, f"{expert.name}.error.txt", msg)
            return expert, None, msg

    results: dict[str, dict] = {}
    status["models"] = {}
    with ThreadPoolExecutor(max_workers=len(experts)) as pool:
        for expert, parsed, err in pool.map(_ask, experts):
            name = expert.name
            if err is None and parsed is not None:
                results[name] = parsed
                status["experts"][name] = "ok"
                primary = getattr(expert, "model", "")
                model_used = getattr(expert, "model_used", None) or primary or "(default)"
                status["models"][name] = model_used
                if getattr(expert, "model_used", None) and expert.model_used != primary:
                    log(f"  council expert '{name}': FELL BACK to model '{expert.model_used}' "
                        f"(primary '{primary or '(default)'}' failed)")
                n = len(parsed.get(list_key) or []) if list_key else "document"
                log(f"  council expert '{name}': {n} item(s)" if list_key
                    else f"  council expert '{name}': ok (document)")
            else:
                status["experts"][name] = f"failed: {err}"
                log(f"  council expert '{name}' FAILED: {err}")

    names = [e.name for e in experts if e.name in results]
    if not names:
        status["error"] = "all council experts failed"
        status["degraded"] = True
        _write(log_dir, "status.json", json.dumps(status, indent=2, default=str))
        log("  council: ALL experts failed — no output for this pass")
        return None, status

    if len(names) < len(experts):
        status["degraded"] = True  # at least one expert dropped out

    # --- Single surviving expert: consensus skipped (degraded) ------------ #
    if len(names) == 1:
        only = results[names[0]]
        if list_key:
            for it in (only.get(list_key) or []):
                it.setdefault("agreement", "single")
                it.setdefault("experts", names)
        else:
            only = {"consensus": only, "disagreements": []}
        only["council"] = names
        only["_experts"] = {names[0]: _contribution(results[names[0]])}
        status["arbiter"] = "none(single-expert)"
        status["degraded"] = True
        _write(log_dir, "status.json", json.dumps(status, indent=2, default=str))
        log(f"  council: single expert ({names[0]}) — consensus skipped (degraded)")
        return only, status

    # --- Arbiter reconciliation with fallback chain ----------------------- #
    payload = {n: _contribution(results[n]) for n in names}
    if list_key:
        arb_prompt = ARBITER_LIST_PROMPT.format(list_key=list_key)
    else:
        arb_prompt = ARBITER_DOC_PROMPT
    arb_prompt += json.dumps(payload, default=str)[:max_arbiter_chars]
    _write(log_dir, "arbiter.input.json", json.dumps(payload, indent=2, default=str))

    by_name = {e.name: e for e in experts}
    order = arbiter_order or DEFAULT_ARBITER_ORDER
    chain = [by_name[n] for n in order if n in by_name]
    # Any remaining experts not named in the order are last-resort arbiters.
    chain += [e for e in experts if e not in chain]

    merged: dict | None = None
    arbiter = None
    for idx, expert in enumerate(chain):
        try:
            raw = expert.complete(arb_prompt)
            _write(log_dir, f"arbiter.{expert.name}.response.txt", raw)
            merged = extract_json(raw)
            arbiter = expert.name if idx == 0 else f"{expert.name}(fallback)"
            if idx != 0:
                status["degraded"] = True
            break
        except Exception as exc:  # noqa: BLE001
            _write(log_dir, f"arbiter.{expert.name}.error.txt", str(exc)[:300])
            log(f"  council: {expert.name} arbiter failed ({str(exc)[:150]})")

    if merged is None:
        # All arbiters failed: fall back programmatically so nothing is hidden.
        if list_key:
            union = [dict(it, agreement="union-fallback") for n in names for it in payload[n]]
            merged = {list_key: union, "disagreements": []}
        else:
            merged = {"consensus": payload[names[0]], "disagreements": []}
        arbiter = "union-fallback"
        status["degraded"] = True
        status["error"] = "arbiter failed; used programmatic union of experts"
        log("  council: ALL arbiters failed — used programmatic union")
    elif not list_key and "consensus" not in merged:
        # Arbiter answered with the bare document instead of wrapping it.
        bare_disagreements = merged.pop("disagreements", [])
        merged = {"consensus": merged, "disagreements": bare_disagreements}

    merged["council"] = names
    merged["arbiter"] = arbiter
    merged["_experts"] = payload
    disagreements = merged.get("disagreements") or []
    status["arbiter"] = arbiter
    status["disagreements"] = len(disagreements)
    if disagreements:
        _write(log_dir, "disagreements.json", json.dumps(disagreements, indent=2, default=str))
    _write(log_dir, "status.json", json.dumps(status, indent=2, default=str))
    count = len(merged.get(list_key) or []) if list_key else 1
    log(f"  council: consensus over {names} (arbiter={arbiter}) -> "
        f"{count} item(s), {len(disagreements)} arbiter-resolved disagreement(s)")
    return merged, status
