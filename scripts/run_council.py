#!/usr/bin/env python3
"""
Run Council of Experts on CVE comparison files.

Reads benchmark/**/comparison.md, calls `council ask --json` for each AI fix section,
and updates benchmark/CWE/CVE/appsec_fixes/pr_NN_verdict.json with a `council` block.

Usage:
    python3 scripts/run_council.py              # all CVEs
    python3 scripts/run_council.py CVE-2023-41080  # single CVE
"""

import json
import re
import subprocess
import sys
from pathlib import Path

BENCHMARK_DIR = Path("benchmark")

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
    result = subprocess.run(
        ["council", "ask", prompt, "--json"],
        capture_output=True, text=True, timeout=600
    )
    if result.returncode != 0:
        raise RuntimeError(f"council failed: {result.stderr}")
    return json.loads(result.stdout)


def extract_classification(answer: str) -> str:
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
    meta, human_fix, ai_fixes = parse_comparison_file(path)
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
    target = sys.argv[1] if len(sys.argv) > 1 else None

    if target:
        files = sorted(BENCHMARK_DIR.glob(f"*/CVE-*/comparison.md"))
        files = [f for f in files if target in str(f)]
        if not files:
            print(f"No comparison.md found for {target} in benchmark/")
            sys.exit(1)
    else:
        files = sorted(BENCHMARK_DIR.glob("*/CVE-*/comparison.md"))

    print(f"Running council on {len(files)} CVE(s)...\n")

    for path in files:
        process_file(path)

    print("\nDone.")


if __name__ == "__main__":
    main()
