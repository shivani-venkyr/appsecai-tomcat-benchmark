"""
Scrape Tomcat security pages and merge results into cve_candidates.json.

Fetches security-10.html and security-11.html, extracts CVEs from 2023
onwards, deduplicates by CVE ID, and skips CVEs that:
  - already have a fixes/ markdown file, OR
  - already have a complete benchmark entry (latest run has pr_found=True)

Existing entries in cve_candidates.json are preserved; new entries are
merged in rather than overwriting the file.

Usage:
    python scripts/scrape_candidates.py \
        [--fixes-dir fixes] \
        [--benchmark-dir benchmark] \
        [--limit 100] \
        [--out cve_candidates.json]
"""

import argparse
import json
import re
import sys
from pathlib import Path
from urllib.request import Request, urlopen

PAGES = [
    ("https://tomcat.apache.org/security-11.html", "11"),
    ("https://tomcat.apache.org/security-10.html", "10"),
]
CUTOFF_YEAR = 2023
SEVERITY_MAP = {"Important": "High"}  # Apache uses Important; we use High
SEVERITY_ORDER = {"Critical": 0, "High": 1, "Moderate": 2, "Low": 3}


def fetch(url: str) -> str:
    req = Request(url, headers={"User-Agent": "Mozilla/5.0 (compatible; appsecai-scraper/1.0)"})
    return urlopen(req, timeout=20).read().decode("utf-8")


def parse_page(html: str, tomcat_version: str) -> list[dict]:
    """Extract CVE entries from a single security page."""
    cves = []

    # Split into release sections. Both pages use <h3> for release dates.
    # security-11: <h3>2026-05-05 Fixed in ...</h3>
    # security-10: <h3>...<span ...>2026-03-23</span> Fixed in ...</h3>
    sections = re.split(r'<h3[^>]*>', html)

    for section in sections[1:]:  # first chunk is pre-header nav
        # Extract year from section — look for a 4-digit year >= 2000
        year_m = re.search(r'\b(20\d{2})\b', section)
        if not year_m:
            continue
        year = int(year_m.group(1))
        if year < CUTOFF_YEAR:
            continue

        # Find all <p> blocks in this section
        for p_m in re.finditer(r'<p>(.*?)</p>', section, re.DOTALL):
            p_html = p_m.group(1)

            # CVE header paragraph: <strong>Severity: Description</strong> ... CVE-XXXX-XXXXX
            strong_m = re.search(
                r'<strong>(Low|Moderate|Important|Critical):\s*(.*?)</strong>',
                p_html, re.DOTALL
            )
            cve_m = re.search(r'\b(CVE-\d{4}-\d+)\b', p_html)

            if not strong_m or not cve_m:
                continue

            severity_raw = strong_m.group(1)
            description = re.sub(r'<[^>]+>', '', strong_m.group(2))
            description = re.sub(r'\s+', ' ', description).strip()
            cve_id = cve_m.group(1)
            severity = SEVERITY_MAP.get(severity_raw, severity_raw)

            # Scan forward from this <p> to the next CVE <strong> or </h3>
            # to scope commit link extraction.
            pos_after_p = p_m.end()
            next_cve = re.search(r'<strong>(?:Low|Moderate|Important|Critical):', section[pos_after_p:])
            window_end = pos_after_p + (next_cve.start() if next_cve else 3000)
            window = section[pos_after_p:window_end]

            # Extract full commit SHAs from GitHub links
            commit_shas = re.findall(
                r'https://github\.com/apache/tomcat/commit/([0-9a-f]{40})',
                window
            )

            cves.append({
                "cve_id": cve_id,
                "severity": severity,
                "short_description": description,
                "fix_commits": commit_shas,
                "fix_year": year,
                "tomcat_version": tomcat_version,
            })

    return cves


def _load_completed_from_benchmark(benchmark_dir: Path) -> set[str]:
    """Return CVE IDs whose latest benchmark run has pr_found=True."""
    completed = set()
    for meta_path in benchmark_dir.glob("*/CVE-*/metadata.json"):
        try:
            meta = json.loads(meta_path.read_text(encoding="utf-8"))
            runs = meta.get("runs", [])
            if runs and runs[-1].get("pr_found", False):
                completed.add(meta_path.parent.name)
        except Exception:
            pass
    return completed


def main(fixes_dir: Path, out_path: Path, benchmark_dir: Path | None = None, limit: int = 100) -> None:
    has_fix = {p.stem.split("_")[0] for p in fixes_dir.glob("CVE-*_before_after.md")}
    print(f"CVEs with existing fixes/ markdown: {len(has_fix)}")

    completed_in_benchmark: set[str] = set()
    if benchmark_dir is not None and benchmark_dir.exists():
        completed_in_benchmark = _load_completed_from_benchmark(benchmark_dir)
        print(f"CVEs completed in benchmark (pr_found=True): {len(completed_in_benchmark)}")

    skip = has_fix | completed_in_benchmark

    # Load existing candidates to preserve manual edits and avoid data loss
    existing_by_id: dict[str, dict] = {}
    if out_path.exists():
        try:
            for entry in json.loads(out_path.read_text(encoding="utf-8")):
                existing_by_id[entry["cve_id"]] = entry
        except Exception as exc:
            print(f"WARNING: could not load {out_path}: {exc}", file=sys.stderr)

    # Scrape fresh data
    scraped_by_id: dict[str, dict] = {}
    for url, version in PAGES:
        print(f"Fetching {url} ...")
        html = fetch(url)
        found = parse_page(html, version)
        print(f"  Found {len(found)} CVEs on security-{version}.html (year >= {CUTOFF_YEAR})")

        for entry in found:
            cid = entry["cve_id"]
            if cid in scraped_by_id:
                # Merge commit SHAs from both pages (backport commits differ)
                existing_commits = scraped_by_id[cid]["fix_commits"]
                for sha in entry["fix_commits"]:
                    if sha not in existing_commits:
                        existing_commits.append(sha)
                scraped_by_id[cid].setdefault("also_tomcat_version", []).append(version)
            else:
                scraped_by_id[cid] = entry

    # Merge scraped data into existing records
    skipped = []
    no_commits = []
    merged: dict[str, dict] = {}

    for cve_id, scraped in sorted(scraped_by_id.items()):
        if cve_id in skip:
            skipped.append(cve_id)
            continue
        if not scraped["fix_commits"]:
            print(f"  WARN: {cve_id} has no commit links — skipping")
            no_commits.append(cve_id)
            continue

        if cve_id in existing_by_id:
            # Preserve existing record; merge in any new commit SHAs only
            record = dict(existing_by_id[cve_id])
            existing_commits = record.get("fix_commits", [])
            for sha in scraped["fix_commits"]:
                if sha not in existing_commits:
                    existing_commits.append(sha)
            record["fix_commits"] = existing_commits
            merged[cve_id] = record
        else:
            merged[cve_id] = scraped

    # Sort by fix_year desc, then severity, then CVE ID
    candidates = sorted(
        merged.values(),
        key=lambda x: (-x.get("fix_year", 0), SEVERITY_ORDER.get(x.get("severity", ""), 99), x["cve_id"]),
    )

    if limit > 0 and len(candidates) > limit:
        print(f"Applying limit: keeping top {limit} of {len(candidates)} candidates")
        candidates = candidates[:limit]

    print(f"\nSkipped (already processed): {len(skipped)}")
    print(f"New candidates written: {len(candidates)}")

    out_path.write_text(json.dumps(candidates, indent=2, ensure_ascii=False) + "\n", encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--benchmark-dir", type=Path, default=Path("benchmark"),
                        help="Path to benchmark dir for completed-CVE dedup (pass empty string to disable)")
    parser.add_argument("--limit", type=int, default=100,
                        help="Max candidates to write (0 = unlimited, default 100)")
    parser.add_argument("--out", type=Path, default=Path("cve_candidates.json"))
    args = parser.parse_args()
    benchmark_dir = args.benchmark_dir if str(args.benchmark_dir) else None
    main(args.fixes_dir, args.out, benchmark_dir, args.limit)
