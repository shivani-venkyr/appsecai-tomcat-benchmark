"""
Generate (or update) all_fixes.md files for council-of-experts review.

Reads fixes/CVE-*_before_after.md (human fix) and fetches the AppSecAI PR diff,
then writes benchmark/CWE-NNN/CVE-XXXX/all_fixes.md.  If the file already
exists and already contains the target PR, the run is skipped.  If the file
exists but is missing the target PR, the new AI Fix section is appended and the
header PR list is updated.

Usage:
    python scripts/generate_all_fixes.py --cve-id CVE-XXXX-XXXXX
    python scripts/generate_all_fixes.py          # all CVEs with a fix but no all_fixes.md
"""

import argparse
import difflib
import re
import subprocess
import sys
from pathlib import Path

from list_pending_cves import list_pending_cves
from utils import find_appsecai_pr, parse_fix_markdown


def fetch_pr_diff(pr_number: int, repo: str) -> str:
    result = subprocess.run(
        ["gh", "pr", "diff", str(pr_number), "--repo", repo],
        capture_output=True, text=True,
    )
    return result.stdout if result.returncode == 0 else ""


def filter_java_diff(diff_text: str) -> str:
    lines = diff_text.splitlines()
    out = []
    in_java = False
    for line in lines:
        if line.startswith("diff --git"):
            in_java = bool(re.search(r'b/.+\.java$', line))
        if in_java:
            out.append(line)
    return "\n".join(out)


def find_cve_dir(cve_id: str, cwe_id: str, benchmark_dir: Path) -> Path:
    cve_dir = benchmark_dir / cwe_id / cve_id
    cve_dir.mkdir(parents=True, exist_ok=True)
    return cve_dir


def process_cve(cve_id: str, fixes_dir: Path, benchmark_dir: Path, repo: str) -> bool:
    md_path = fixes_dir / f"{cve_id}_before_after.md"
    if not md_path.exists():
        print(f"  {cve_id}: no fix markdown, skipping")
        return False

    data = parse_fix_markdown(md_path)
    cwe = data.get("cwe", "CWE-UNKNOWN")
    cwe_full = data.get("cwe_full", cwe)
    severity = data.get("severity", "Unknown")
    after_file = data.get("after_file", "")

    pr = find_appsecai_pr(cve_id, repo, file_path=after_file or None)
    if not pr:
        print(f"  {cve_id}: no AppSecAI PR found, skipping")
        return False

    pr_number = pr["number"]
    diff = fetch_pr_diff(pr_number, repo)
    if not diff:
        print(f"  {cve_id}: could not fetch PR #{pr_number} diff, skipping")
        return False

    java_diff = filter_java_diff(diff)
    cve_dir = find_cve_dir(cve_id, cwe, benchmark_dir)

    # Render human fix as unified diff (before → after) per file
    after_blocks = data.get("after_blocks", [])
    before_blocks = data.get("before_blocks", [])
    if not after_blocks:
        print(f"  {cve_id}: WARNING — no After code blocks found; human fix section will be empty")
    before_by_file = {b["file"]: b["lines"] for b in before_blocks}
    human_fix_parts = []
    for block in after_blocks:
        fname = block["file"]
        before_lines = before_by_file.get(fname, [])
        after_lines = block["lines"]
        diff_lines = list(difflib.unified_diff(
            before_lines, after_lines,
            fromfile=f"a/{fname}", tofile=f"b/{fname}",
            lineterm="",
        ))
        if diff_lines:
            human_fix_parts.append("```diff\n" + "\n".join(diff_lines) + "\n```")
    human_fix_section = "\n\n".join(human_fix_parts) if human_fix_parts else "```diff\n\n```"

    ai_fix_section = f"## AI Fix (AppSecAI PR #{pr_number})\n\n```diff\n{java_diff}\n```\n"
    out_path = cve_dir / "all_fixes.md"

    if out_path.exists():
        existing = out_path.read_text(encoding="utf-8")
        if f"PR #{pr_number}" in existing:
            print(f"  {cve_id}: PR #{pr_number} already in {out_path.name}, skipping")
            return False
        # Append new AI Fix section and update the header PR list
        pr_header_re = re.compile(r'(\*\*PR:\*\* )([^\n]+)')
        def _add_pr(m: re.Match) -> str:
            return m.group(1) + m.group(2).rstrip() + f", #{pr_number}"
        updated = pr_header_re.sub(_add_pr, existing, count=1)
        updated = updated.rstrip("\n") + "\n\n" + ai_fix_section
        out_path.write_text(updated, encoding="utf-8")
        print(f"  {cve_id}: appended PR #{pr_number} to {out_path.name}")
        return True

    content = f"""# {cve_id} All Fixes

**CVE:** {cve_id} | **CWE:** {cwe_full} | **Severity:** {severity} | **PR:** #{pr_number}

## Human Fix

{human_fix_section}

{ai_fix_section}"""
    out_path.write_text(content, encoding="utf-8")
    print(f"  {cve_id}: wrote {out_path.name} (PR #{pr_number})")
    return True


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-id", help="Single CVE to process")
    parser.add_argument("--repo", default="AppSecureAI/appsecai-tomcat-benchmark")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--benchmark-dir", type=Path, default=Path("benchmark"))
    args = parser.parse_args()

    if args.cve_id:
        cve_ids = [args.cve_id]
    else:
        cve_ids = list_pending_cves(args.fixes_dir, args.benchmark_dir)

    print(f"Processing {len(cve_ids)} CVE(s)...")
    count = sum(
        1 for cve_id in cve_ids
        if process_cve(cve_id, args.fixes_dir, args.benchmark_dir, args.repo)
    )
    print(f"Done. Updated {count} all_fixes.md file(s).")


if __name__ == "__main__":
    main()
