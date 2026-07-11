"""
List CVEs that have a fix markdown but no complete benchmark entry.

A CVE is "complete" when its most recent run in metadata.json has pr_found=True.
CVEs whose latest run missed (pr_found=False) are returned so generate_all_fixes.py
can re-attempt them on the next AppSecAI run.

Can be imported as a module or run as a CLI tool.
"""

import json
from pathlib import Path


def list_pending_cves(fixes_dir: Path, benchmark_dir: Path) -> list[str]:
    has_fix = {
        p.name.replace("_before_after.md", "")
        for p in fixes_dir.glob("CVE-*_before_after.md")
    }

    complete = set()
    for meta_path in benchmark_dir.glob("*/CVE-*/metadata.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
        except Exception:
            continue
        runs = meta.get("runs", [])
        if runs and runs[-1].get("pr_found", False):
            complete.add(meta_path.parent.name)

    return sorted(has_fix - complete)


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="List CVEs pending AppSecAI processing")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--benchmark-dir", type=Path, default=Path("benchmark"))
    args = parser.parse_args()

    cves = list_pending_cves(args.fixes_dir, args.benchmark_dir)
    if cves:
        print(",".join(cves))
