#!/usr/bin/env python3
"""
Run Council of Experts on CVE comparison files.

Reads benchmark/**/comparison.md, calls `council ask --json` for each AI fix section,
and updates benchmark/CWE/CVE/appsec_fixes/pr_NN_verdict.json with a `council` block.

Usage:
    python3 scripts/run_council.py              # all CVEs
    python3 scripts/run_council.py CVE-2023-41080  # single CVE
"""

import argparse
import json
import re
import sys
from pathlib import Path


def _ensure_council_importable() -> None:
    """Add vendor/ to sys.path so council_of_experts is importable without installation."""
    vendor = Path(__file__).parent.parent / "vendor"
    if str(vendor) not in sys.path:
        sys.path.insert(0, str(vendor))

PROMPT_TEMPLATE = """\
You are evaluating an AI-generated security fix against the correct human fix for a real CVE in Apache Tomcat.

CVE: {cve_id}
CWE: {cwe}
Severity: {severity}

## Human Fix (reference — this is the correct patch)
{human_fix}

## AI Fix (AppSecAI{pr_label})
{ai_fix}

Classify the AI fix as exactly one of:
- Accepted: the AI fix adequately addresses the vulnerability (equivalent to or better than the human fix)
- Rejected: the AI fix is incomplete, a miss, a false positive, or only partially addresses the vulnerability

There is no middle ground. A partial fix is Rejected. Start your answer with "Accepted" or "Rejected", \
then explain: what the AI fix got right, what it missed or got wrong, and how it compares to the human fix. \
End with a confidence level (High / Medium / Low).\
"""


def parse_comparison_file(path: Path) -> tuple[dict, str, list[dict]]:
    """
    Returns:
        meta: {cve_id, cwe, severity}
        human_fix: str
        ai_fixes: list of {pr_label, pr_num, content}
    """
    text = path.read_text(encoding="utf-8")
    sections = re.split(r'\n(?=## )', text)

    header = sections[0]
    meta_m = re.search(
        r'\*\*CVE:\*\*\s*(CVE-[\w-]+).*?\*\*CWE:\*\*\s*(CWE-\d+[^|]+?)\s*\|.*?\*\*Severity:\*\*\s*(\w+)',
        header
    )
    if not meta_m:
        raise ValueError(f"Could not parse metadata from {path}")

    meta = {
        "cve_id": meta_m.group(1).strip(),
        "cwe": meta_m.group(2).strip(),
        "severity": meta_m.group(3).strip(),
    }

    human_fix = ""
    ai_fixes = []

    for section in sections[1:]:
        if section.startswith("## Human Fix"):
            human_fix = section[len("## Human Fix"):].strip()
        elif section.startswith("## AI Fix"):
            header_line = section.splitlines()[0]
            pr_m = re.search(r'PR #(\d+)', header_line)
            pr_num = int(pr_m.group(1)) if pr_m else None
            pr_label = f" PR #{pr_m.group(1)}" if pr_m else ""
            content = "\n".join(section.splitlines()[1:]).strip()
            ai_fixes.append({"pr_label": pr_label, "pr_num": pr_num, "content": content})

    return meta, human_fix, ai_fixes


def run_council(prompt: str) -> dict:
    _ensure_council_importable()
    from council_of_experts.consensus import run_council as _run_council
    from council_of_experts.experts.claude import ClaudeExpert
    from council_of_experts.experts.codex import CodexExpert

    # The council CLI wraps prompts with a JSON shape so experts return structured
    # output. Replicate that here so the consensus has answer/key_points/confidence.
    shape = {
        "answer": "<your full answer; markdown allowed>",
        "key_points": ["<key point>"],
        "confidence": "high|medium|low",
    }
    wrapped = (
        f"{prompt}\n\n"
        f"Return STRICT JSON only (no markdown fences, no prose outside JSON) matching:\n"
        f"{json.dumps(shape, indent=2)}"
    )

    merged, status = _run_council(
        wrapped,
        experts=[ClaudeExpert(timeout=600), CodexExpert(timeout=600)],
        log=lambda _: None,
    )

    if merged is None:
        raise RuntimeError(f"All council experts failed: {status['experts']}")
    return merged


def extract_classification(answer: str) -> str:
    # Anchor to the start — the prompt instructs the council to open with the verdict word
    m = re.match(r'\s*(Accepted|Rejected)\b', answer.strip(), re.IGNORECASE)
    if m:
        return m.group(1).capitalize()
    # Fallback: scan for first occurrence (older responses or format drift)
    m = re.search(r'\b(Accepted|Rejected)\b', answer, re.IGNORECASE)
    return m.group(1).capitalize() if m else "Unknown"


def already_judged(cve_dir: Path, pr_num: int | None) -> bool:
    """Return True if this PR's verdict.json already has a council block."""
    if pr_num is None:
        return False
    verdict_path = cve_dir / "appsec_fixes" / f"pr_{pr_num}_verdict.json"
    if not verdict_path.exists():
        return False
    verdict = json.loads(verdict_path.read_text())
    return "council" in verdict


def update_verdict(cve_dir: Path, pr_num: int | None, council_result: dict, run_date: str | None = None) -> None:
    """Merge council data into pr_NN_verdict.json, creating the file if needed."""
    if pr_num is None:
        return

    verdict_path = cve_dir / "appsec_fixes" / f"pr_{pr_num}_verdict.json"
    verdict_path.parent.mkdir(parents=True, exist_ok=True)

    if verdict_path.exists():
        verdict = json.loads(verdict_path.read_text())
    else:
        verdict = {
            "pr_number": pr_num,
            "pr_url": None,
            "date": run_date,
            "system_version": None,
            "status": "pr_created",
            "human_verdict": None,
        }

    verdict["council"] = {
        "classification": council_result["classification"],
        "confidence": council_result["confidence"],
        "reasoning": council_result["reasoning"],
        "key_points": council_result["key_points"],
        "disagreements": council_result["disagreements"],
        "experts": council_result["experts"],
    }

    verdict_path.write_text(json.dumps(verdict, indent=2, ensure_ascii=False) + "\n")


def process_file(path: Path) -> None:
    try:
        meta, human_fix, ai_fixes = parse_comparison_file(path)
    except ValueError as e:
        print(f"ERROR: could not parse {path}: {e}")
        return
    cve_dir = path.parent

    for fix in ai_fixes:
        pr_num = fix["pr_num"]

        if already_judged(cve_dir, pr_num):
            print(f"  {meta['cve_id']}{fix['pr_label']} ... already judged, skipping")
            continue

        prompt = PROMPT_TEMPLATE.format(
            cve_id=meta["cve_id"],
            cwe=meta["cwe"],
            severity=meta["severity"],
            human_fix=human_fix,
            pr_label=fix["pr_label"],
            ai_fix=fix["content"],
        )

        print(f"  {meta['cve_id']}{fix['pr_label']} ... ", end="", flush=True)
        try:
            raw = run_council(prompt)
            classification = extract_classification(raw["consensus"]["answer"])
            result = {
                "classification": classification,
                "confidence": raw["consensus"].get("confidence", ""),
                "reasoning": raw["consensus"]["answer"],
                "key_points": raw["consensus"].get("key_points", []),
                "disagreements": raw.get("disagreements", []),
                "experts": {k: v.get("answer", "") for k, v in raw.get("_experts", {}).items()},
            }
            update_verdict(cve_dir, pr_num, result)
            print(f"{classification} ({result['confidence']} confidence)")
        except Exception as e:
            print(f"ERROR: {e}")


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("cve_id", nargs="?", default=None, help="Single CVE to process")
    parser.add_argument("--benchmark-dir", type=Path, default=Path("benchmark"))
    args = parser.parse_args()

    benchmark_dir = args.benchmark_dir
    target = args.cve_id

    if target:
        files = sorted(benchmark_dir.glob("*/CVE-*/comparison.md"))
        files = [f for f in files if target == f.parent.name]
        if not files:
            print(f"No comparison.md found for {target} in {benchmark_dir}/ — skipping")
            sys.exit(0)
    else:
        files = sorted(benchmark_dir.glob("*/CVE-*/comparison.md"))

    print(f"Running council on {len(files)} CVE(s)...\n")

    for path in files:
        process_file(path)

    print("\nDone.")


if __name__ == "__main__":
    main()
