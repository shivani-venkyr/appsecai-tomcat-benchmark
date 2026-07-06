#!/usr/bin/env python3
"""
Run Council of Experts on all CVE comparison files.
Reads comparisons/*.md, calls `council ask --json` for each AI fix section,
saves results to pipeline_data/council_results.json.

Usage:
    python3 scripts/run_council.py              # all CVEs
    python3 scripts/run_council.py CVE-2023-41080  # single CVE
"""

import json
import re
import subprocess
import sys
from pathlib import Path

COMPARISONS_DIR = Path("comparisons")
OUT_FILE = Path("pipeline_data/council_results.json")

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


def parse_comparison_file(path: Path) -> dict:
    """
    Returns:
        meta: {cve_id, cwe, severity}
        human_fix: str
        ai_fixes: list of {pr_label, content}
    """
    text = path.read_text(encoding="utf-8")
    sections = re.split(r'\n(?=## )', text)

    header = sections[0]
    meta_m = re.search(
        r'\*\*CVE:\*\*\s*(CVE-[\w-]+).*?\*\*CWE:\*\*\s*(CWE-\d+[^|]+?)\s*\|.*?\*\*Severity:\*\*\s*(\w+)',
        header
    )
    if not meta_m:
        raise ValueError(f"Could not parse metadata from {path.name}")

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
            # Extract PR label from header line
            header_line = section.splitlines()[0]
            pr_m = re.search(r'PR #([\w/]+)', header_line)
            pr_label = f" PR #{pr_m.group(1)}" if pr_m else ""
            content = "\n".join(section.splitlines()[1:]).strip()
            ai_fixes.append({"pr_label": pr_label, "content": content})

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
    """Pull 'Accepted' or 'Rejected' from the start of the consensus answer."""
    m = re.search(r'\b(Accepted|Rejected)\b', answer, re.IGNORECASE)
    return m.group(1).capitalize() if m else "Unknown"


def process_file(path: Path) -> list[dict]:
    meta, human_fix, ai_fixes = parse_comparison_file(path)
    results = []

    for fix in ai_fixes:
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
            results.append({
                "cve_id": meta["cve_id"],
                "pr_label": fix["pr_label"].strip(),
                "classification": classification,
                "reasoning": raw["consensus"]["answer"],
                "key_points": raw["consensus"].get("key_points", []),
                "confidence": raw["consensus"].get("confidence", ""),
                "disagreements": raw.get("disagreements", []),
                "experts": {k: v.get("answer", "") for k, v in raw.get("_experts", {}).items()},
            })
            print(f"{classification} ({raw['consensus'].get('confidence', '?')} confidence)")
        except Exception as e:
            print(f"ERROR: {e}")
            results.append({
                "cve_id": meta["cve_id"],
                "pr_label": fix["pr_label"].strip(),
                "classification": "Error",
                "error": str(e),
            })

    return results


def main():
    target = sys.argv[1] if len(sys.argv) > 1 else None
    files = sorted(COMPARISONS_DIR.glob("CVE-*.md"))
    if target:
        files = [f for f in files if target in f.name]
        if not files:
            print(f"No comparison file found for {target}")
            sys.exit(1)

    # Load existing results
    existing = json.loads(OUT_FILE.read_text()) if OUT_FILE.exists() else {}

    print(f"Running council on {len(files)} CVE(s)...\n")
    all_results = dict(existing)

    for path in files:
        results = process_file(path)
        for r in results:
            key = r["cve_id"] + (f"_{r['pr_label']}" if r["pr_label"] else "")
            all_results[key] = r

        OUT_FILE.write_text(json.dumps(all_results, indent=2, ensure_ascii=False) + "\n")

    print(f"\nDone. Results saved to {OUT_FILE}")
    print(f"Total entries: {len(all_results)}")


if __name__ == "__main__":
    main()
