"""
Shared utilities for the AppSecAI benchmark pipeline scripts.
"""

import json
import re
import subprocess
from pathlib import Path


def parse_fix_markdown(md_path: Path) -> dict:
    """Parse a CVE before/after fix markdown file.

    Returns a dict with keys:
      cve_id, cwe, cwe_full, cwe_description, severity, d1_score,
      affected_component, before_blocks, after_blocks, after_file
    """
    data = {}
    before_blocks: list[dict] = []
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
                        data["cwe"] = cwe_m.group(0) if cwe_m else value
                        desc_m = re.search(r'\((.+?)\)', value)
                        data["cwe_description"] = desc_m.group(1) if desc_m else ""
                    elif field == "Severity":
                        data["severity"] = value
                    elif field == "D1 Score":
                        d1_m = re.match(r'(\d+)', value)
                        data["d1_score"] = int(d1_m.group(1)) if d1_m else 0
                    elif field == "Affected Component":
                        data["affected_component"] = re.sub(r'`', '', value).strip()
                elif line.startswith("## Before"):
                    state = "SCAN_BEFORE_PATH"
                elif line.startswith("## After"):
                    state = "SCAN_AFTER_PATH"

            elif state == "SCAN_BEFORE_PATH":
                stripped = line.strip()
                if stripped.startswith("## After"):
                    current_file = ""
                    state = "SCAN_AFTER_PATH"
                elif stripped.startswith("## ") and not stripped.startswith("## Before"):
                    break
                else:
                    m = re.match(r'^`([^`]+\.java)`', stripped)
                    if m:
                        current_file = m.group(1)
                    elif re.match(r'^```', stripped) and current_file:
                        current_lines = []
                        state = "IN_BEFORE"

            elif state == "IN_BEFORE":
                if line.strip() == "```":
                    before_blocks.append({"file": current_file, "lines": current_lines})
                    current_file = ""
                    current_lines = []
                    state = "SCAN_BEFORE_PATH"
                else:
                    current_lines.append(line)

            elif state == "SCAN_AFTER_PATH":
                stripped = line.strip()
                if stripped.startswith("## ") and not stripped.startswith("## After"):
                    break  # left the After section
                m = re.match(r'^`([^`]+\.java)`', stripped)
                if m:
                    current_file = m.group(1)
                elif re.match(r'^```', stripped) and current_file:
                    # Only open a block when a file path preceded it; bare fences
                    # without a file path are illustrative blocks, not fix code.
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

    data["before_blocks"] = before_blocks
    data["after_blocks"] = after_blocks
    data["after_file"] = after_blocks[0]["file"] if after_blocks else ""
    return data


def find_appsecai_pr(cve_id: str, repo: str, file_path: str | None = None) -> dict | None:
    """Find the most recent AppSecAI PR for a given CVE in the benchmark repo.

    Tries three match strategies in order:
      1. CVE ID in PR title (single-CVE PRs)
      2. CVE ID in PR body (grouped PRs)
      3. Filename in PR title (last resort — may false-match)
    """
    result = subprocess.run(
        [
            "gh", "pr", "list",
            "--repo", repo,
            "--state", "all",
            "--json", "number,url,headRefName,title,body,createdAt",
            "--limit", "500",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        print(f"  WARNING: gh pr list failed: {result.stderr.strip()}")
        return None

    prs = json.loads(result.stdout)
    appsecai_prs = [p for p in prs if p["headRefName"].startswith("appsecai/fix-group/")]

    # 1. CVE ID in title (most reliable — works for single-CVE PRs)
    matches = [p for p in appsecai_prs if cve_id in p["title"]]
    if matches:
        matches.sort(key=lambda p: p["createdAt"], reverse=True)
        return matches[0]

    # 2. CVE ID in PR body (grouped PRs list each CVE in the description)
    matches = [p for p in appsecai_prs if cve_id in (p.get("body") or "")]
    if matches:
        matches.sort(key=lambda p: p["createdAt"], reverse=True)
        print(f"  (matched by CVE ID in PR body — grouped PR)")
        return matches[0]

    # 3. Filename in title (last resort — may match wrong PR if two CVEs share a file)
    if file_path:
        filename = Path(file_path).name
        matches = [p for p in appsecai_prs if filename in p["title"]]
        if matches:
            matches.sort(key=lambda p: p["createdAt"], reverse=True)
            print(f"  (matched by filename {filename!r} — verify this is the right PR)")
            return matches[0]

    return None
