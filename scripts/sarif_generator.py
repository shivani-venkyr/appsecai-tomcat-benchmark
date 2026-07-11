import argparse
import json
import re
import subprocess
import tempfile
from pathlib import Path


LEVEL_MAP = {"Low": "note", "Moderate": "warning", "High": "error"}


def _parse_affected_component(raw: str) -> dict:
    parts = re.split(r'\s*→\s*', raw, maxsplit=1)
    if len(parts) < 2:
        raise ValueError(f"Affected Component has no → separator: {raw!r}")

    # Extract first backtick-enclosed .java file from LHS; handles multi-file LHS like
    # `File1.java` + `File2.java` by using only the first file for line-number lookup.
    java_files = re.findall(r'`([^`]+\.java)`', parts[0])
    lhs = java_files[0] if java_files else parts[0].strip().strip('`')
    rhs = parts[1].strip()

    # Extract backtick-enclosed tokens from the RHS; prefer those over raw text
    backtick_tokens = re.findall(r'`([^`]+)`', rhs)
    method_tokens = [t for t in backtick_tokens if not t.endswith('.java')]

    # Prefer tokens that look like method calls (end with '()'); fall back to all tokens
    method_call_tokens = [t for t in method_tokens if t.endswith('()')]
    if method_call_tokens:
        all_methods = method_call_tokens
    elif method_tokens:
        all_methods = method_tokens
    else:
        rhs_clean = re.sub(r'`', '', rhs).strip()
        all_methods = [t.strip() for t in rhs_clean.split(',')]

    first = all_methods[0].rstrip('()')

    # Only treat as ClassName.method if it matches that exact pattern (not e.g. HTTP/0.9)
    class_method = re.match(r'^([A-Z]\w+)\.(\w+)', first)
    if class_method:
        return {"grep_term": class_method.group(1), "is_class": True, "all_methods": all_methods}

    # If the token is a bare class name (uppercase, no parens) OR multi-word free text
    # (spaces indicate a description, not a method name), fall back to the LHS file stem
    # so find_declaration_line searches for the class declaration in the original file.
    if first and not first[0].isdigit() and (' ' in first or first[0].isupper()) and lhs.endswith('.java'):
        file_stem = Path(lhs).stem
        return {"grep_term": file_stem, "is_class": True, "all_methods": all_methods}

    return {"grep_term": first, "is_class": False, "all_methods": all_methods}


def _clean_before_lines(lines: list[str], is_class: bool) -> list[str]:
    if is_class:
        trimmed = []
        depth = 0
        found_open = False
        for line in lines:
            trimmed.append(line)
            depth += line.count('{') - line.count('}')
            if depth > 0:
                found_open = True
            if found_open and depth == 0:
                break
        lines = trimmed if found_open else lines

    result = []
    for line in lines:
        if re.match(r'\s*//\s*\.\.\.', line):
            continue
        if '←' in line:
            line = re.sub(r'\s*//.*←.*$', '', line).rstrip()
        result.append(line)
    return result


def parse_markdown(path: Path) -> dict:
    data = {}
    state = "SCANNING_TABLE"
    before_lines = []
    before_file_path = None
    after_file_path = None
    done = False
    before_captured = False  # True once the first Before block is fully read

    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.rstrip("\n")

            if state == "SCANNING_TABLE":
                m = re.match(r'\|\s*\*\*(.+?)\*\*\s*\|\s*(.+?)\s*\|', line)
                if m:
                    field, value = m.group(1), m.group(2)
                    if field == "CVE ID":
                        data["cve_id"] = value
                    elif field == "CWE":
                        cwe_m = re.search(r'CWE-\d+', value)
                        desc_m = re.search(r'\((.+?)\)', value)
                        data["cwe_id"] = cwe_m.group(0) if cwe_m else value
                        data["cwe_description"] = desc_m.group(1) if desc_m else ""
                    elif field == "Severity":
                        data["severity"] = value
                    elif field == "D1 Score":
                        d1_m = re.match(r'(\d+)', value)
                        data["d1_score"] = int(d1_m.group(1)) if d1_m else 0
                    elif field == "Affected Component":
                        data.update(_parse_affected_component(value))
                    elif field in ("Fix Commit", "Fix Commit(s)"):
                        data["fix_commits"] = re.findall(r'`([0-9a-f]+)`', value)
                    elif field == "Line Override":
                        lo_m = re.match(r'(\d+)', value)
                        data["line_override"] = int(lo_m.group(1)) if lo_m else None
                elif line.startswith("## Before"):
                    state = "SCANNING_BEFORE"

            elif state == "SCANNING_BEFORE":
                if line.startswith("## After"):
                    state = "SCANNING_AFTER"
                elif not before_captured:
                    m = re.match(r'`([^`]+\.java)`', line)
                    if m:
                        before_file_path = m.group(1)
                    elif re.match(r'^```\w', line.strip()):
                        state = "IN_BEFORE_CODE"

            elif state == "IN_BEFORE_CODE":
                if line.strip() == "```":
                    before_captured = True
                    state = "SCANNING_BEFORE"  # go back — multi-file Before or ## After may follow
                else:
                    before_lines.append(line)

            elif state == "SCANNING_AFTER":
                m = re.match(r'`([^`]+\.java)`', line)
                if m:
                    after_file_path = m.group(1)
                elif re.match(r'^```\w', line.strip()):
                    state = "IN_AFTER_CODE"

            elif state == "IN_AFTER_CODE":
                if line.strip() == "```":
                    done = True
                    break

    if not done:
        raise ValueError(f"{path.name}: did not reach end of After code block")

    data["before_lines"] = _clean_before_lines(before_lines, data.get("is_class", False))
    data["before_file_path"] = before_file_path
    paths = {p for p in [before_file_path, after_file_path] if p}
    data["files_touched"] = len(paths)
    data.setdefault("fix_commits", [])

    for key in ["cve_id", "cwe_id", "severity", "d1_score"]:
        if key not in data:
            raise ValueError(f"{path.name}: missing field '{key}'")

    return data


def find_declaration_line(src_file: Path, grep_term: str, is_class: bool) -> int | None:
    if not src_file.exists():
        return None

    escaped = re.escape(grep_term)
    if is_class:
        patterns = [re.compile(rf'\bclass\s+{escaped}\b')]
    else:
        patterns = [
            # Explicit visibility modifier (public/protected/private)
            re.compile(rf'\b(?:private|protected|public)\b.*\b{escaped}\b'),
            # Package-private or other declarations: returnType methodName(
            re.compile(rf'(?:(?:static|final|native|synchronized|abstract)\s+)*[\w<>\[\]]+\s+{escaped}\s*\('),
        ]

    with open(src_file, encoding="utf-8") as f:
        lines = f.readlines()

    for pattern in patterns:
        for lineno, line in enumerate(lines, start=1):
            if pattern.search(line):
                return lineno
    return None


def build_sarif(cve_data: dict, start_line: int, end_line: int, snippet_lines: list | None = None) -> dict:
    cve_id = cve_data["cve_id"]
    cwe_id = cve_data["cwe_id"]
    cwe_desc = cve_data["cwe_description"]
    severity = cve_data["severity"]
    all_methods = cve_data["all_methods"]
    file_path = cve_data["before_file_path"]
    filename = Path(file_path).name

    if len(all_methods) == 1:
        msg = f"{cve_id} ({severity}): {cwe_id} {cwe_desc} in {filename} {all_methods[0]}."
    else:
        methods_str = ", ".join(all_methods)
        msg = f"{cve_id} ({severity}): {cwe_id} {cwe_desc} in {filename}. Affected: {methods_str}."

    snippet = "\n".join(snippet_lines if snippet_lines is not None else cve_data["before_lines"])

    return {
        "version": "2.1.0",
        "$schema": "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "tomcat-cve-benchmark",
                        "rules": [
                            {
                                "id": cve_id,
                                "name": f"Tomcat {cve_id}",
                                "shortDescription": {"text": f"{cwe_id} {cwe_desc}"},
                                "properties": {
                                    "tags": [cwe_id],
                                    "cwe": [cwe_id],
                                },
                            }
                        ],
                    }
                },
                "results": [
                    {
                        "ruleId": cve_id,
                        "level": LEVEL_MAP.get(severity, "note"),
                        "message": {"text": msg},
                        "locations": [
                            {
                                "physicalLocation": {
                                    "artifactLocation": {"uri": file_path},
                                    "region": {
                                        "startLine": start_line,
                                        "endLine": end_line,
                                        "startColumn": 1,
                                        "endColumn": 80,
                                        "snippet": {"text": snippet},
                                    },
                                }
                            }
                        ],
                        "properties": {
                            "cve": cve_id,
                            "patch_complexity_score": cve_data["d1_score"],
                            "files_touched": cve_data["files_touched"],
                            **( {"fix_commits": cve_data["fix_commits"]} if cve_data.get("fix_commits") else {} ),
                        },
                    }
                ],
            }
        ],
    }


def _get_vulnerable_content(tomcat_dir: Path, file_path: str, fix_commit: str) -> str | None:
    """Return the file content at fix_commit^ (the vulnerable state), or None on failure."""
    result = subprocess.run(
        ["git", "show", f"{fix_commit}^:{file_path}"],
        capture_output=True, text=True,
        cwd=tomcat_dir,
    )
    return result.stdout if result.returncode == 0 else None


def main(fixes_dir: Path, sarif_dir: Path, cve_ids: list[str] | None = None) -> None:
    sarif_dir.mkdir(parents=True, exist_ok=True)
    base_dir = Path(__file__).parent.parent
    tomcat_dir = base_dir / "tomcat"

    all_md_paths = sorted(fixes_dir.glob("CVE-*_before_after.md"))
    if cve_ids:
        md_paths = [p for p in all_md_paths if any(p.name == cid + "_before_after.md" for cid in cve_ids)]
    else:
        md_paths = all_md_paths

    for md_path in md_paths:
        try:
            cve_data = parse_markdown(md_path)
        except Exception as e:
            print(f"ERROR: skipping {md_path.name}: {e}")
            continue
        cve_id = cve_data["cve_id"]

        # Get the file at the vulnerable state (parent of the fix commit) so line
        # numbers and snippets reflect the code AppSecAI needs to detect and fix.
        fix_commit = cve_data["fix_commits"][0] if cve_data.get("fix_commits") else None
        vulnerable_content = None
        if fix_commit and tomcat_dir.is_dir():
            vulnerable_content = _get_vulnerable_content(tomcat_dir, cve_data["before_file_path"], fix_commit)
            if vulnerable_content:
                print(f"  {cve_id}: source at {fix_commit}^")
            else:
                print(f"  WARN: {cve_id}: could not retrieve source at {fix_commit}^, falling back to current")

        # Use a tempfile with vulnerable content when available; fall back to the
        # static copy in the repo root when not.
        tmp_path = None
        if vulnerable_content is not None:
            tmp = tempfile.NamedTemporaryFile(mode='w', suffix='.java', delete=False, encoding='utf-8')
            tmp.write(vulnerable_content)
            tmp.close()
            lookup_path = Path(tmp.name)
            tmp_path = lookup_path
        else:
            lookup_path = base_dir / cve_data["before_file_path"]

        try:
            if cve_data.get("line_override"):
                start_line = cve_data["line_override"]
            else:
                start_line = find_declaration_line(lookup_path, cve_data["grep_term"], cve_data["is_class"])
                if start_line is None:
                    print(f"WARN: {cve_data['grep_term']!r} not found in {lookup_path}, using startLine=1")
                    start_line = 1

            end_line = start_line + len(cve_data["before_lines"]) - 1

            snippet_lines = None
            if lookup_path.exists():
                actual_lines = lookup_path.read_text(encoding="utf-8", errors="replace").splitlines()
                end_line = min(end_line, len(actual_lines))
                end_line = max(end_line, start_line)  # SARIF requires endLine >= startLine
                if start_line > 1:
                    candidate = actual_lines[start_line - 1 : end_line]
                    if candidate:
                        snippet_lines = candidate
        finally:
            if tmp_path is not None:
                tmp_path.unlink(missing_ok=True)

        sarif = build_sarif(cve_data, start_line, end_line, snippet_lines)

        out_path = sarif_dir / f"{cve_id}.sarif"
        out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SARIF 2.1.0 files from CVE markdown")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--sarif-dir", type=Path, default=Path("sarif"))
    parser.add_argument("--cve-ids", default=None, help="Comma-separated CVE IDs to process (default: all)")
    args = parser.parse_args()
    cve_ids = [c.strip() for c in args.cve_ids.split(',')] if args.cve_ids else None
    main(args.fixes_dir, args.sarif_dir, cve_ids)
