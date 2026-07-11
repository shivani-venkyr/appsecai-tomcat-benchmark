"""
Create or update the benchmark/ folder structure after an AppSecAI run.

Structure produced:
    benchmark/
      CWE-NNN/
        CVE-XXXX-XXXXX/
          metadata.json
          human_fix.md
          verdicts/
            pr_NN.diff
            pr_NN_verdict.json

Usage:
    python scripts/organize_benchmark.py \
        --cve-id CVE-XXXX-XXXXX \
        --fixes-dir fixes \
        --candidates cve_candidates.json \
        --benchmark-dir benchmark
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path


_EXT_TO_LANG = {
    ".java": "Java",
    ".py": "Python",
    ".js": "JavaScript",
    ".ts": "TypeScript",
    ".go": "Go",
    ".rb": "Ruby",
    ".php": "PHP",
    ".cs": "C#",
    ".cpp": "C++", ".cc": "C++", ".cxx": "C++",
    ".c": "C",
    ".swift": "Swift",
    ".kt": "Kotlin",
}


def _detect_language(after_blocks: list[dict]) -> str:
    for block in after_blocks:
        lang = _EXT_TO_LANG.get(Path(block["file"]).suffix.lower())
        if lang:
            return lang
    return "Unknown"


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
                elif line.startswith("## After"):
                    state = "SCAN_AFTER_PATH"

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

    data["after_blocks"] = after_blocks
    data["after_file"] = after_blocks[0]["file"] if after_blocks else ""
    return data


def find_appsecai_pr(cve_id: str, repo: str, file_path: str | None = None) -> dict | None:
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


def main(cve_id: str, fixes_dir: Path, candidates_path: Path, benchmark_dir: Path, repo: str, system_version: str | None = None) -> None:
    md_path = fixes_dir / f"{cve_id}_before_after.md"
    if not md_path.exists():
        print(f"ERROR: {md_path} not found", file=sys.stderr)
        sys.exit(1)

    parsed = parse_fix_markdown(md_path)
    cwe = parsed.get("cwe", "CWE-UNKNOWN")

    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    candidate = next((c for c in candidates if c["cve_id"] == cve_id), None)
    if candidate is None:
        print(f"  WARNING: {cve_id} not found in {candidates_path} — candidate fields will be empty")
        candidate = {}
    # Create folder structure
    cve_dir = benchmark_dir / cwe / cve_id
    fixes_out_dir = cve_dir / "verdicts"
    cve_dir.mkdir(parents=True, exist_ok=True)
    fixes_out_dir.mkdir(exist_ok=True)

    # Find AppSecAI PR and write fix artifacts
    after_file = parsed.get("after_file") or None
    pr = find_appsecai_pr(cve_id, repo, file_path=after_file)
    if pr:
        pr_number = pr["number"]

        # Preserve council block and human_verdict if verdict already exists
        verdict_path = fixes_out_dir / f"pr_{pr_number}_verdict.json"
        existing_verdict = json.loads(verdict_path.read_text(encoding="utf-8")) if verdict_path.exists() else {}
        verdict: dict = {
            "pr_number": pr_number,
            "pr_url": pr["url"],
            "date": date.today().isoformat(),
            "system_version": system_version,
            "status": "pr_created",
            "human_verdict": existing_verdict.get("human_verdict"),
        }
        if "council" in existing_verdict:
            verdict["council"] = existing_verdict["council"]
        verdict_path.write_text(json.dumps(verdict, indent=2) + "\n", encoding="utf-8")
        print(f"Wrote {fixes_out_dir}/pr_{pr_number}_verdict.json")
    else:
        print("No AppSecAI PR found — verdicts/ left empty")

    # Write metadata.json after PR lookup so runs reflects the actual outcome.
    meta_path = cve_dir / "metadata.json"
    existing_meta = json.loads(meta_path.read_text(encoding="utf-8")) if meta_path.exists() else {}
    new_run: dict = {
        "run_date": date.today().isoformat(),
        "system_version": system_version,
        "pr_found": pr is not None,
    }
    if pr is not None:
        new_run["pr_number"] = pr["number"]
    metadata = {
        **existing_meta,
        # Re-parsed from markdown
        "cve_id": cve_id,
        "language": _detect_language(parsed.get("after_blocks", [])),
        "cwe": cwe,
        "cwe_description": parsed.get("cwe_description", existing_meta.get("cwe_description", "")),
        "severity": parsed.get("severity", ""),
        "d1_score": parsed.get("d1_score", 0),
        "affected_component": parsed.get("affected_component", ""),
        # From cve_candidates.json
        "short_description": candidate.get("short_description", existing_meta.get("short_description", "")),
        "fix_year": candidate.get("fix_year", existing_meta.get("fix_year")),
        "runs": existing_meta.get("runs", []) + [new_run],
    }
    meta_path.write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {cve_dir}/metadata.json")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--candidates", type=Path, default=Path("cve_candidates.json"))
    parser.add_argument("--benchmark-dir", type=Path, default=Path("benchmark"))
    parser.add_argument("--repo", default="AppSecureAI/appsecai-tomcat-benchmark")
    parser.add_argument("--system-version", default=None)
    args = parser.parse_args()
    main(args.cve_id, args.fixes_dir, args.candidates, args.benchmark_dir, args.repo, args.system_version)
