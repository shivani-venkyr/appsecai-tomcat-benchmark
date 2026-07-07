"""
One-time migration: builds benchmark/ from legacy pipeline_data/ and fixes/comparisons/.
Already run — kept for reference. Source files have since been deleted/moved.

Reads:
  pipeline_data/appsecai_runs.json    — legacy run history (now deleted)
  pipeline_data/council_results.json  — legacy council verdicts (now deleted)
  cve_candidates.json                 — fix_commits, short_description, tomcat_version
  fixes/CVE-*_before_after.md         — CWE, severity, D1, human fix
  comparisons/CVE-*.md                — human vs AI comparison text

Writes:
  benchmark/CWE-NNN/CVE-XXXX/
    metadata.json
    human_fix.md
    comparison.md
    appsec_fixes/
      pr_NN_verdict.json          (includes council block if available)
      pr_NN.diff                  (only with --fetch-diffs)
      run_YYYY-MM-DD_verdict.json (for runs with no PR)

Usage:
    python scripts/migrate_to_benchmark.py
    python scripts/migrate_to_benchmark.py --fetch-diffs
    python scripts/migrate_to_benchmark.py --dry-run
"""

import json
import re
import subprocess
import sys
from pathlib import Path

REPO = "AppSecureAI/appsecai-tomcat-benchmark"
DRY_RUN = "--dry-run" in sys.argv
FETCH_DIFFS = "--fetch-diffs" in sys.argv


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
                        data["cwe_full"] = value
                        cwe_m = re.search(r'CWE-\d+', value)
                        data["cwe_id"] = cwe_m.group(0) if cwe_m else value
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


def fetch_pr_diff(pr_number: int) -> str:
    result = subprocess.run(
        ["gh", "pr", "diff", str(pr_number), "--repo", REPO],
        capture_output=True, text=True,
    )
    return result.stdout if result.returncode == 0 else ""


def write(path: Path, content: str) -> None:
    if DRY_RUN:
        return
    path.write_text(content, encoding="utf-8")


def main() -> None:
    runs = json.loads(Path("pipeline_data/appsecai_runs.json").read_text())  # legacy
    council = json.loads(Path("pipeline_data/council_results.json").read_text())  # legacy
    candidates = {c["cve_id"]: c for c in json.loads(Path("cve_candidates.json").read_text())}

    if DRY_RUN:
        print("DRY RUN — no files will be written\n")

    benchmark_dir = Path("benchmark")
    fixes_dir = Path("fixes")
    comparisons_dir = Path("comparisons")

    for cve_id, run_data in sorted(runs.items()):
        md_path = fixes_dir / f"{cve_id}_before_after.md"
        if not md_path.exists():
            print(f"SKIP {cve_id}: no fix markdown")
            continue

        parsed = parse_fix_markdown(md_path)
        cwe_id = parsed.get("cwe_id", "CWE-UNKNOWN")
        cve_dir = benchmark_dir / cwe_id / cve_id
        appsec_dir = cve_dir / "appsec_fixes"

        print(f"\n{cve_id}  ({cwe_id})")

        if not DRY_RUN:
            appsec_dir.mkdir(parents=True, exist_ok=True)

        # metadata.json
        candidate = candidates.get(cve_id, {})
        metadata = {
            "cve_id": cve_id,
            "cwe": cwe_id,
            "cwe_description": parsed.get("cwe_full", cwe_id),
            "severity": parsed.get("severity", ""),
            "d1_score": parsed.get("d1_score", 0),
            "affected_component": parsed.get("affected_component", ""),
            "short_description": candidate.get("short_description", ""),
            "fix_commits": candidate.get("fix_commits", []),
            "fix_year": candidate.get("fix_year"),
            "tomcat_version": candidate.get("tomcat_version", ""),
            "also_tomcat_version": candidate.get("also_tomcat_version", []),
            "submitted_to_appsecai": run_data.get("submitted_to_appsecai", False),
        }
        write(cve_dir / "metadata.json", json.dumps(metadata, indent=2) + "\n")
        print(f"  metadata.json")

        # human_fix.md
        after_file = parsed.get("after_file", "")
        file_header = f"`{after_file}`\n\n" if after_file else ""
        human_fix_content = (
            f"# {cve_id} — Human Fix\n\n"
            + file_header
            + "```java\n"
            + "\n".join(parsed["after_lines"])
            + "\n```\n"
        )
        write(cve_dir / "human_fix.md", human_fix_content)
        print(f"  human_fix.md")

        # comparison.md
        comparison_src = comparisons_dir / f"{cve_id}.md"
        if comparison_src.exists():
            write(cve_dir / "comparison.md", comparison_src.read_text(encoding="utf-8"))
            print(f"  comparison.md")
        else:
            print(f"  WARNING: no comparisons/{cve_id}.md found")

        # pr_NN_verdict.json / run_YYYY-MM-DD_verdict.json per run
        for run in run_data.get("runs", []):
            pr_str = run.get("pr_created")
            pr_num = int(pr_str.strip("#")) if pr_str else None
            run_date = run.get("date", "unknown")

            council_key = f"{cve_id}_PR #{pr_num}" if pr_num else None
            council_data = council.get(council_key)

            verdict = {
                "pr_number": pr_num,
                "pr_url": f"https://github.com/{REPO}/pull/{pr_num}" if pr_num else None,
                "date": run_date,
                "system_version": run.get("system_version"),
                "status": "pr_created" if pr_num else "no_pr",
                "human_verdict": None,
            }
            if council_data:
                verdict["council"] = {
                    "classification": council_data.get("classification"),
                    "confidence": council_data.get("confidence"),
                    "reasoning": council_data.get("reasoning"),
                    "key_points": council_data.get("key_points", []),
                    "disagreements": council_data.get("disagreements", []),
                    "experts": council_data.get("experts", {}),
                }

            if pr_num:
                verdict_name = f"pr_{pr_num}_verdict.json"
            else:
                verdict_name = f"run_{run_date}_verdict.json"

            write(appsec_dir / verdict_name, json.dumps(verdict, indent=2, ensure_ascii=False) + "\n")
            council_tag = " + council" if council_data else ""
            print(f"  appsec_fixes/{verdict_name}{council_tag}")

            if pr_num and FETCH_DIFFS:
                diff = fetch_pr_diff(pr_num)
                if diff:
                    write(appsec_dir / f"pr_{pr_num}.diff", diff)
                    print(f"  appsec_fixes/pr_{pr_num}.diff")
                else:
                    print(f"  WARNING: could not fetch pr_{pr_num}.diff")

    print("\nMigration complete.")
    if not FETCH_DIFFS:
        print("Tip: re-run with --fetch-diffs to also pull PR diffs from GitHub.")


if __name__ == "__main__":
    main()
