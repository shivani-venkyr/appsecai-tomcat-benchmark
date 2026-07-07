"""
Generate comparison markdown files for council-of-experts review.

Reads fixes/CVE-*_before_after.md (human fix) and fetches the AppSecAI PR diff,
then writes benchmark/CWE-NNN/CVE-XXXX/comparison.md.

Usage:
    python scripts/generate_comparison.py --cve-id CVE-XXXX-XXXXX
    python scripts/generate_comparison.py          # all CVEs with a fix but no comparison
"""

import argparse
import json
import re
import subprocess
import sys
from pathlib import Path


def parse_fix_markdown(md_path: Path) -> dict:
    data = {}
    after_blocks: list[dict] = []
    current_file = ""
    current_lines: list[str] = []
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
                        data["cwe_full"] = value
                        cwe_m = re.search(r'CWE-\d+', value)
                        data["cwe_id"] = cwe_m.group(0) if cwe_m else value
                    elif field == "Severity":
                        data["severity"] = value
                elif line.startswith("## After"):
                    state = "SCAN_AFTER_PATH"
            elif state == "SCAN_AFTER_PATH":
                stripped = line.strip()
                if stripped.startswith("## ") and not stripped.startswith("## After"):
                    break  # left the After section
                if stripped.startswith("`java/"):
                    current_file = stripped.strip("`")
                elif re.match(r'^```', stripped):
                    current_lines = []
                    state = "IN_AFTER"
            elif state == "IN_AFTER":
                if line.strip() == "```":
                    after_blocks.append({"file": current_file, "lines": current_lines})
                    current_file = ""
                    current_lines = []
                    state = "SCAN_AFTER_PATH"
                else:
                    current_lines.append(line)
    data["after_blocks"] = after_blocks
    data["after_file"] = after_blocks[0]["file"] if after_blocks else ""
    data["after_lines"] = after_blocks[0]["lines"] if after_blocks else []
    return data


def find_appsecai_pr(cve_id: str, repo: str, file_path: str | None = None) -> dict | None:
    result = subprocess.run(
        ["gh", "pr", "list", "--repo", repo, "--state", "all",
         "--json", "number,url,headRefName,title,createdAt", "--limit", "100"],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None
    prs = json.loads(result.stdout)
    appsecai_prs = [p for p in prs if p["headRefName"].startswith("appsecai/fix-group/")]

    matches = [p for p in appsecai_prs if cve_id in p["title"]]
    if matches:
        matches.sort(key=lambda p: p["createdAt"], reverse=True)
        return matches[0]

    # Fallback: match by Java filename in title (handles grouped PRs with generic titles)
    if file_path:
        filename = Path(file_path).name
        matches = [p for p in appsecai_prs if filename in p["title"]]
        if matches:
            matches.sort(key=lambda p: p["createdAt"], reverse=True)
            print(f"  (matched by filename {filename!r} — grouped PR)")
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
    cwe_id = data.get("cwe_id", "CWE-UNKNOWN")
    cwe_full = data.get("cwe_full", cwe_id)
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
    cve_dir = find_cve_dir(cve_id, cwe_id, benchmark_dir)

    # Render all After blocks (handles fixes touching multiple files)
    after_blocks = data.get("after_blocks", [])
    if after_blocks:
        human_fix_parts = []
        for block in after_blocks:
            file_hdr = f"`{block['file']}`\n\n" if block["file"] else ""
            human_fix_parts.append(file_hdr + "```java\n" + "\n".join(block["lines"]) + "\n```")
        human_fix_section = "\n\n".join(human_fix_parts)
    else:
        human_fix_section = "```java\n\n```"

    content = f"""# {cve_id} Fix Comparison

**CVE:** {cve_id} | **CWE:** {cwe_full} | **Severity:** {severity} | **PR:** #{pr_number}

## Human Fix

{human_fix_section}

## AI Fix (AppSecAI PR #{pr_number})

```diff
{java_diff}
```
"""
    out_path = cve_dir / "comparison.md"
    out_path.write_text(content, encoding="utf-8")
    print(f"  {cve_id}: wrote {out_path} (PR #{pr_number})")
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
        cve_ids = sorted(
            p.name.replace("_before_after.md", "")
            for p in args.fixes_dir.glob("CVE-*_before_after.md")
        )

    print(f"Generating comparisons for {len(cve_ids)} CVE(s)...")
    count = sum(
        1 for cve_id in cve_ids
        if process_cve(cve_id, args.fixes_dir, args.benchmark_dir, args.repo)
    )
    print(f"Done. Wrote {count} comparison file(s).")


if __name__ == "__main__":
    main()
