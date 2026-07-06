"""
Generate a CVE fix markdown by calling the Claude API with the raw git diff.

Usage:
    python scripts/generate_markdown.py --cve-id CVE-XXXX-XXXXX \
        [--candidates pipeline_data/cve_candidates.json] \
        [--fixes-dir fixes] \
        [--tomcat-repo https://github.com/apache/tomcat.git]
"""

import argparse
import json
import re
import subprocess
import sys
import tempfile
from pathlib import Path

import anthropic


D1_THRESHOLDS = [10, 50, 200, 500]


def d1_score(lines_changed: int) -> int:
    for i, threshold in enumerate(D1_THRESHOLDS, start=1):
        if lines_changed <= threshold:
            return i
    return 5


def fetch_diff(sha: str, tomcat_repo: str) -> str:
    with tempfile.TemporaryDirectory() as tmpdir:
        tmp = Path(tmpdir) / "tomcat"
        tmp.mkdir()
        subprocess.run(["git", "init"], cwd=tmp, check=True, capture_output=True)
        subprocess.run(
            ["git", "remote", "add", "origin", tomcat_repo],
            cwd=tmp, check=True, capture_output=True,
        )
        result = subprocess.run(
            ["git", "fetch", "--depth=2", "origin", sha],
            cwd=tmp, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git fetch failed for {sha}:\n{result.stderr}")

        result = subprocess.run(
            ["git", "show", "--diff-filter=M", sha],
            cwd=tmp, capture_output=True, text=True,
        )
        if result.returncode != 0:
            raise RuntimeError(f"git show failed for {sha}:\n{result.stderr}")
        return result.stdout


def count_java_lines(diff_text: str) -> int:
    in_java = False
    added = removed = 0
    for line in diff_text.splitlines():
        if line.startswith("diff --git"):
            in_java = bool(re.search(r'b/.+\.java$', line))
        elif in_java:
            if line.startswith("+") and not line.startswith("+++"):
                added += 1
            elif line.startswith("-") and not line.startswith("---"):
                removed += 1
    return added + removed


PROMPT_TEMPLATE = """\
You are a security engineer writing a CVE fix documentation file for an AppSecAI benchmark.

## Your task
Analyze the git diff below and produce a `fixes/{cve_id}_before_after.md` file documenting the vulnerability and its fix.

## CVE Metadata
- CVE ID: {cve_id}
- Severity: {severity}
- Description: {short_description}
- Fix commit: {fix_commit}
- D1 Score: {d1_score} ({lines_changed} Java lines changed)

## Raw Git Diff
```diff
{diff_text}
```

## Format — follow this example EXACTLY

Here is a completed example for a different CVE. Match this structure precisely:

---
# CVE-2023-28709 — Before/After Fix

| Field | Value |
|---|---|
| **CVE ID** | CVE-2023-28709 |
| **CWE** | CWE-193 (Off-by-one Error) |
| **Severity** | Moderate |
| **Affected Component** | `Parameters.java` → `addParameter()` |
| **Fix Commit** | `d53d8e7f` |
| **Follow-up Commit** | *(none — single-version fix)* |
| **D1 Score** | 1 (4 Java lines changed, ≤10) |
| **Fix Complexity Notes** | One method, two-line structural change: move the increment after the guard and tighten `>` to `>=`. The subtle issue is that pre-incrementing before the check means the count reaches `limit+1` on the failing call, not `limit`. Any subsequent parsing code that reads `parameterCount` as an indicator of stored parameters would see a value one higher than the actual map size, which could be exploited across repeated partial parse attempts to evade the limit. An AI that swaps `>` to `>=` without also moving the increment (or vice versa) will produce an off-by-one in the other direction. |

---

## Before (Vulnerable)

`java/org/apache/tomcat/util/http/Parameters.java`

```java
    public void addParameter(String key, String value) throws IllegalStateException {{

        if (key == null) {{
            return;
        }}

        parameterCount++;
        if (limit > -1 && parameterCount > limit) {{
            setParseFailedReason(FailReason.TOO_MANY_PARAMETERS);
            throw new IllegalStateException(sm.getString("parameters.maxCountFail", Integer.valueOf(limit)));
        }}

        paramHashValues.computeIfAbsent(key, k -> new ArrayList<>(1)).add(value);
    }}
```

---

## After (Patched)

`java/org/apache/tomcat/util/http/Parameters.java`

```java
    public void addParameter(String key, String value) throws IllegalStateException {{

        if (key == null) {{
            return;
        }}

        if (limit > -1 && parameterCount >= limit) {{
            setParseFailedReason(FailReason.TOO_MANY_PARAMETERS);
            throw new IllegalStateException(sm.getString("parameters.maxCountFail", Integer.valueOf(limit)));
        }}
        parameterCount++;

        paramHashValues.computeIfAbsent(key, k -> new ArrayList<>(1)).add(value);
    }}
```

---

## Explanation

`addParameter` enforces a configurable ceiling on the total number of request parameters to prevent memory exhaustion attacks. In the original code, `parameterCount` was incremented before the limit check, meaning the counter reached `limit + 1` on the failing call even though the parameter was never stored.

Changing to `parameterCount >= limit` with a post-increment enforces the boundary at exactly `limit` parameters, making `parameterCount` an accurate count of successfully added parameters at all times.

---

## Rules for your output
- Determine the CWE from the nature of the vulnerability (e.g. CWE-193 off-by-one, CWE-79 XSS, CWE-400 resource exhaustion, CWE-20 improper input validation).
- **Affected Component** must be: `` `FileName.java` → `methodName()` `` (method-level) or `` `FileName.java` → `ClassName.method()` `` (inner/named class).
- File paths in `## Before` and `## After` must start with `java/` (e.g. `java/org/apache/...`).
- Before block: full method body as it was before the fix (clean Java, no `+`/`-` diff markers).
- After block: full method body after the fix (clean Java, no `+`/`-` diff markers).
- Fix Complexity Notes: explain what makes this fix subtle or easy to get wrong for an AI — what an AI might do incorrectly and why.
- Output ONLY the markdown content. No preamble, no explanation, nothing outside the markdown.
"""


def call_claude(prompt: str) -> str:
    client = anthropic.Anthropic()
    message = client.messages.create(
        model="claude-sonnet-4-6",
        max_tokens=4096,
        messages=[{"role": "user", "content": prompt}],
    )
    return message.content[0].text


def main(
    cve_id: str,
    candidates_path: Path,
    fixes_dir: Path,
    tomcat_repo: str,
) -> None:
    candidates = json.loads(candidates_path.read_text(encoding="utf-8"))
    entry = next((c for c in candidates if c["cve_id"] == cve_id), None)
    if entry is None:
        print(f"ERROR: {cve_id} not found in {candidates_path}", file=sys.stderr)
        sys.exit(1)

    sha = entry["fix_commits"][0]
    print(f"Fetching diff for {cve_id} @ {sha[:8]} ...")
    diff_text = fetch_diff(sha, tomcat_repo)

    lines_changed = count_java_lines(diff_text)
    score = d1_score(lines_changed)
    print(f"  {lines_changed} Java lines changed, D1={score}")

    prompt = PROMPT_TEMPLATE.format(
        cve_id=cve_id,
        severity=entry["severity"],
        short_description=entry["short_description"],
        fix_commit=sha[:8],
        d1_score=score,
        lines_changed=lines_changed,
        diff_text=diff_text[:12000],  # cap at ~12k chars to stay within context
    )

    print("Calling Claude API ...")
    markdown = call_claude(prompt)

    fixes_dir.mkdir(parents=True, exist_ok=True)
    out_path = fixes_dir / f"{cve_id}_before_after.md"
    out_path.write_text(markdown, encoding="utf-8")
    print(f"Wrote {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--cve-id", required=True)
    parser.add_argument("--candidates", type=Path, default=Path("pipeline_data/cve_candidates.json"))
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--tomcat-repo", default="https://github.com/apache/tomcat.git")
    args = parser.parse_args()
    main(args.cve_id, args.candidates, args.fixes_dir, args.tomcat_repo)
