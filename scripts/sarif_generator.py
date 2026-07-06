import re
import json
import argparse
from pathlib import Path


LEVEL_MAP = {"Low": "note", "Moderate": "warning", "High": "error"}


def _parse_affected_component(raw: str) -> dict:
    parts = re.split(r'\s*→\s*', raw, maxsplit=1)
    if len(parts) < 2:
        raise ValueError(f"Affected Component has no → separator: {raw!r}")

    rhs = parts[1].strip()

    # Extract backtick-enclosed tokens from the RHS; prefer those over raw text
    backtick_tokens = re.findall(r'`([^`]+)`', rhs)
    method_tokens = [t for t in backtick_tokens if not t.endswith('.java')]

    if method_tokens:
        all_methods = method_tokens
    else:
        rhs_clean = re.sub(r'`', '', rhs).strip()
        all_methods = [t.strip() for t in rhs_clean.split(',')]

    first = all_methods[0].rstrip('()')

    # Only treat as ClassName.method if it matches that exact pattern (not e.g. HTTP/0.9)
    class_method = re.match(r'^([A-Z]\w+)\.(\w+)', first)
    if class_method:
        return {"grep_term": class_method.group(1), "is_class": True, "all_methods": all_methods}
    else:
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
                m = re.match(r'`([^`]+\.java)`', line)
                if m:
                    before_file_path = m.group(1)
                elif re.match(r'^```\w', line.strip()):
                    state = "IN_BEFORE_CODE"

            elif state == "IN_BEFORE_CODE":
                if line.strip() == "```":
                    state = "SCANNING_AFTER"
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


def main(fixes_dir: Path, sarif_dir: Path, tomcat_dir: Path) -> None:
    sarif_dir.mkdir(parents=True, exist_ok=True)
    base_dir = Path(__file__).parent.parent

    for md_path in sorted(fixes_dir.glob("CVE-*.md")):
        cve_data = parse_markdown(md_path)
        cve_id = cve_data["cve_id"]

        src_file = base_dir / cve_data["before_file_path"]

        if cve_data.get("line_override"):
            start_line = cve_data["line_override"]
        else:
            start_line = find_declaration_line(src_file, cve_data["grep_term"], cve_data["is_class"])
            if start_line is None:
                print(f"WARN: {cve_data['grep_term']!r} not found in {src_file}, using startLine=1")
                start_line = 1

        end_line = start_line + len(cve_data["before_lines"]) - 1

        # Resolve snippet and cap endLine against actual file content.
        # When startLine is precise (>1): use actual file lines so snippet matches
        # what AppSecAI reads from the committed source.
        # When startLine=1 (fallback): keep fix-file Before lines so the snippet
        # still describes the vulnerable code, but still cap endLine at file length.
        snippet_lines = None
        if src_file.exists():
            actual_lines = src_file.read_text(encoding="utf-8", errors="replace").splitlines()
            end_line = min(end_line, len(actual_lines))
            if start_line > 1:
                snippet_lines = actual_lines[start_line - 1 : end_line]

        sarif = build_sarif(cve_data, start_line, end_line, snippet_lines)

        out_path = sarif_dir / f"{cve_id}.sarif"
        out_path.write_text(json.dumps(sarif, indent=2, ensure_ascii=False), encoding="utf-8")
        print(f"Wrote {out_path}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Generate SARIF 2.1.0 files from CVE markdown")
    parser.add_argument("--fixes-dir", type=Path, default=Path("fixes"))
    parser.add_argument("--sarif-dir", type=Path, default=Path("sarif"))
    parser.add_argument("--tomcat-dir", type=Path, default=Path("tomcat"))
    args = parser.parse_args()
    main(args.fixes_dir, args.sarif_dir, args.tomcat_dir)
