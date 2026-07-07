"""
Create or update the benchmark/ folder structure after an AppSecAI run.

Structure produced:
    benchmark/
      CWE-NNN/
        CVE-XXXX-XXXXX/
          metadata.json
          human_fix.md
          appsec_fixes/
            pr_NN.diff
            pr_NN_verdict.json

Usage:
    python scripts/organize_benchmark.py \
        --cve-id CVE-XXXX-XXXXX \
        --fixes-dir fixes \
        --candidates pipeline_data/cve_candidates.json \
        --benchmark-dir benchmark
"""

import argparse
import json
import re
import subprocess
import sys
from datetime import date
from pathlib import Path


def parse_fix_markdown(md_path: Path) -> dict:
    data = {}
    after_lines = []
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
                    elif field == "Severity":
                        data["severity"] = value
                    elif field == "D1 Score":
                        d1_m = re.match(r'(\d+)', value)
                        data["d1_score"] = int(d1_m.group(1)) if d1_m else 0
                    elif field == "Affected Component":
                        data["affected_component"] = re.sub(r'`', '', value).strip()
                elif line.startswith("## After"):
                    state = "SCAN_AFTER"

            elif state == "SCAN_AFTER":
                if re.match(r'^```\w', line.strip()):
                    state = "IN_AFTER"

            elif state == "IN_AFTER":
                if line.strip() == "```":
                    break
                after_lines.append(line)

    data["after_lines"] = after_lines
    return data


def find_appsecai_pr(cve_id: str, repo: str) -> dict | None:
    result = subprocess.run(
        [
            "gh", "pr", "list",
            "--repo", repo,
            "--state", "all",
            "--json", "number,url,headRefName,title,createdAt",
            "--limit", "100",
        ],
        capture_output=True, text=True,
    )
    if result.returncode != 0:
        return None

    prs = json.loads(result.stdout)

    # Match by CVE ID in the PR title — AppSecAI titles include the CVE ID directly
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


def main(cve_id: str, fixes_dir: Path, candidates_path: Path, benchmark_dir: Path, repo: str, system_version: str | None = None) -> None:
    md_path = fixes_dir / f"{cve_id}_before_after.md"
    if not md_path.exists():
        print(f"ERROR: {md_path} not found", file=sys.stderr)
        sys.exit(1)

    parsed = parse_fix_markdown(md_path)
    cwe = parsed.get("cwe", "CWE-UNKNOWN")

    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    candidate = next((c for c in candidates if c["cve_id"] == cve_id), {})
    version = candidate.get("tomcat_version", "unknown")

    # Create folder structure
    cve_dir = benchmark_dir / cwe / cve_id
    fixes_out_dir = cve_dir / "appsec_fixes"
    cve_dir.mkdir(parents=True, exist_ok=True)
    fixes_out_dir.mkdir(exist_ok=True)

    # Write metadata.json
    metadata = {
        "cve_id": cve_id,
        "cwe": cwe,
        "severity": parsed.get("severity", ""),
        "d1_score": parsed.get("d1_score", 0),
        "affected_component": parsed.get("affected_component", ""),
        "tomcat_version": version,
        "fix_commit": candidate.get("fix_commits", [None])[0],
    }
    (cve_dir / "metadata.json").write_text(json.dumps(metadata, indent=2) + "\n", encoding="utf-8")
    print(f"Wrote {cve_dir}/metadata.json")

    # Write human_fix.md
    human_fix_content = f"# {cve_id} — Human Fix\n\n```java\n" + "\n".join(parsed["after_lines"]) + "\n```\n"
    (cve_dir / "human_fix.md").write_text(human_fix_content, encoding="utf-8")
    print(f"Wrote {cve_dir}/human_fix.md")

    # Find AppSecAI PR and write fix artifacts
    pr = find_appsecai_pr(cve_id, repo)
    if pr:
        pr_number = pr["number"]
        diff = fetch_pr_diff(pr_number, repo)

        (fixes_out_dir / f"pr_{pr_number}.diff").write_text(diff, encoding="utf-8")
        print(f"Wrote {fixes_out_dir}/pr_{pr_number}.diff")

        verdict = {
            "pr_number": pr_number,
            "pr_url": pr["url"],
            "date": date.today().isoformat(),
            "system_version": system_version,
            "status": "pr_created",
            "human_verdict": None,
        }
        (fixes_out_dir / f"pr_{pr_number}_verdict.json").write_text(
            json.dumps(verdict, indent=2) + "\n", encoding="utf-8"
        )
        print(f"Wrote {fixes_out_dir}/pr_{pr_number}_verdict.json")
    else:
        print("No AppSecAI PR found — appsec_fixes/ left empty")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--candidates", type=Path, default=Path("pipeline_data/cve_candidates.json"))
    parser.add_argument("--benchmark-dir", type=Path, default=Path("benchmark"))
    parser.add_argument("--repo", default="AppSecureAI/appsecai-tomcat-benchmark")
    parser.add_argument("--system-version", default=None)
    args = parser.parse_args()
    main(args.cve_id, args.fixes_dir, args.candidates, args.benchmark_dir, args.repo, args.system_version)
