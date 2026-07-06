"""
Generate comparison markdown files for council-of-experts review.

Reads fixes/CVE-*_before_after.md (human fix) and fetches the AppSecAI PR diff,
then writes comparisons/CVE-*.md in the format expected by run_council.py.

Usage:
    python scripts/generate_comparison.py --cve-id CVE-XXXX-XXXXX
    python scripts/generate_comparison.py          # all CVEs that have a fix but no comparison
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def parse_fix_markdown(md_path: Path) -> dict:
    data = {}
    after_lines = []
    after_file = ""
    state = "TABLE"

    with open(md_path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")
            if state == "TABLE":
                m = re.match(r'\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|', line)
                if m:
                    field, value = m.group(1), m.group(2)
                    if field == "CVE ID":
                        data["cve_id"] = value
                    elif field == "CWE":
                        data["cwe"] = value
                    elif field == "Severity":
                        data["severity"] = value
                elif line.startswith("## After"):
                    state = "SCAN_AFTER_PATH"
            elif state == "SCAN_AFTER_PATH":
                stripped = line.strip()
                if stripped.startswith("`java/"):
                    after_file = stripped.strip("`")
                elif re.match(r'^```', stripped):
                    state = "IN_AFTER"
            elif state == "IN_AFTER":
                if line.strip() == "```":
                    break
                after_lines.append(line)

    data["after_file"] = after_file
    data["after_lines"] = after_lines
    return data


def find_appsecai_pr(cve_id: str, repo: str) -> dict | None:
    result = subprocess.run(
        ["gh", "pr", "list", "--repo", repo, "--state", "all",
         "--json", "number,url,headRefName,title,createdAt", "--limit", "100"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    prs = json.loads(result.stdout)
    matches = [
        p for p in prs
        if p["headRefName"].startswith("appsecai/fix-group/") and cve_id in p["title"]
    ]
    if matches:
        matches.sort(key=lambda p: p["createdAt"], reverse=True)
        return matches[0]
    return None


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


def process_cve(cve_id: str, fixes_dir: Path, comparisons_dir: Path, repo: str) -> bool:
    md_path = fixes_dir / f"{cve_id}_before_after.md"
    if not md_path.exists():
        print(f"  {cve_id}: no fix markdown, skipping")
        return False

    data = parse_fix_markdown(md_path)
    cwe = data.get("cwe", "CWE-UNKNOWN")
    severity = data.get("severity", "Unknown")
    human_fix = "\n".join(data["after_lines"])
    after_file = data.get("after_file", "")

    pr = find_appsecai_pr(cve_id, repo)
    if not pr:
        print(f"  {cve_id}: no AppSecAI PR found, skipping")
        return False

    pr_number = pr["number"]
    diff = fetch_pr_diff(pr_number, repo)
    if not diff:
        print(f"  {cve_id}: could not fetch PR #{pr_number} diff, skipping")
        return False

    java_diff = filter_java_diff(diff)
    file_header = f"`{after_file}`\n\n" if after_file else ""

    content = f"""# {cve_id} Fix Comparison

**CVE:** {cve_id} | **CWE:** {cwe} | **Severity:** {severity} | **PR:** #{pr_number}

## Human Fix

{file_header}```java
{human_fix}
```

## AI Fix (AppSecAI PR #{pr_number})

```diff
{java_diff}
```
"""
    comparisons_dir.mkdir(exist_ok=True)
    out_path = comparisons_dir / f"{cve_id}.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"  {cve_id}: wrote {out_path} (PR #{pr_number})")
    return True


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-id", help="Single CVE to process")
    parser.add_argument("--repo", default="AppSecureAI/appsecai-tomcat-benchmark")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--comparisons-dir", type=Path, default=Path("comparisons"))
    args = parser.parse_args()

    if args.cve_id:
        cve_ids = [args.cve_id]
    else:
        cve_ids = sorted(
            p.name.replace("_before_after.md", "")
            for p in args.fixes_dir.glob("CVE-*_before_after.md")
            if not (args.comparisons_dir / (p.name.replace("_before_after.md", "") + ".md")).exists()
        )

    print(f"Generating comparisons for {len(cve_ids)} CVE(s)...")
    count = sum(
        1 for cve_id in cve_ids
        if process_cve(cve_id, args.fixes_dir, args.comparisons_dir, args.repo)
    )
    print(f"Done. Wrote {count} comparison file(s).")


if __name__ == "__main__":
    main()
