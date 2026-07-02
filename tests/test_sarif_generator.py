import json
import re
from pathlib import Path
import pytest
from sarif_generator import parse_markdown, find_declaration_line, build_sarif, main, _clean_before_lines

# All tests must run from workspace root: /Users/shivani/appsecai-internship/
# Run with: pytest tests/ -v


def test_parse_markdown_table_fields():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["cve_id"] == "CVE-2023-41080"
    assert data["cwe_id"] == "CWE-601"
    assert data["cwe_description"] == "URL Redirection to Untrusted Site — Open Redirect"
    assert data["severity"] == "Moderate"
    assert data["d1_score"] == 1


def test_parse_markdown_before_block():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["before_file_path"] == "java/org/apache/catalina/authenticator/FormAuthenticator.java"
    assert data["files_touched"] == 1
    assert len(data["before_lines"]) > 0
    joined = "\n".join(data["before_lines"])
    assert "protected String savedRequestURL(Session session)" in joined


def test_parse_markdown_affected_component_simple():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["grep_term"] == "savedRequestURL"
    assert data["is_class"] is False
    assert data["all_methods"] == ["savedRequestURL()"]


def test_parse_markdown_affected_component_dotted():
    data = parse_markdown(Path("fixes/CVE-2026-34483_before_after.md"))
    assert data["grep_term"] == "RequestElement"
    assert data["is_class"] is True
    assert data["all_methods"] == ["RequestElement.addElement()", "RequestURIElement.addElement()"]


def test_parse_markdown_low_severity():
    data = parse_markdown(Path("fixes/CVE-2026-24880_before_after.md"))
    assert data["severity"] == "Low"
    assert data["d1_score"] == 3
    assert data["grep_term"] == "parseChunkHeader"
    assert data["is_class"] is False


def test_find_declaration_line_method():
    src = Path("tomcat/java/org/apache/catalina/authenticator/FormAuthenticator.java")
    assert find_declaration_line(src, "savedRequestURL", is_class=False) == 755


def test_find_declaration_line_method_chunked():
    src = Path("tomcat/java/org/apache/coyote/http11/filters/ChunkedInputFilter.java")
    assert find_declaration_line(src, "parseChunkHeader", is_class=False) == 365


def test_find_declaration_line_class():
    src = Path("tomcat/java/org/apache/catalina/valves/AbstractAccessLogValve.java")
    assert find_declaration_line(src, "RequestElement", is_class=True) == 1343


def test_find_declaration_line_missing():
    src = Path("tomcat/java/org/apache/catalina/authenticator/FormAuthenticator.java")
    assert find_declaration_line(src, "nonexistentMethod", is_class=False) is None


def test_find_declaration_line_file_missing():
    assert find_declaration_line(Path("tomcat/java/does/not/Exist.java"), "foo", is_class=False) is None


_MODERATE_CVE = {
    "cve_id": "CVE-2023-41080",
    "cwe_id": "CWE-601",
    "cwe_description": "URL Redirection to Untrusted Site — Open Redirect",
    "severity": "Moderate",
    "d1_score": 1,
    "before_file_path": "java/org/apache/catalina/authenticator/FormAuthenticator.java",
    "before_lines": [
        "protected String savedRequestURL(Session session) {",
        "    return null;",
        "}",
    ],
    "files_touched": 1,
    "grep_term": "savedRequestURL",
    "is_class": False,
    "all_methods": ["savedRequestURL()"],
}


def test_build_sarif_top_level_structure():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    assert sarif["version"] == "2.1.0"
    assert "$schema" in sarif
    assert len(sarif["runs"]) == 1


def test_build_sarif_tool_driver():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    driver = sarif["runs"][0]["tool"]["driver"]
    assert driver["name"] == "tomcat-cve-benchmark"
    rules = driver["rules"]
    assert len(rules) == 1
    assert rules[0]["id"] == "CVE-2023-41080"
    assert rules[0]["properties"]["tags"] == ["CWE-601"]
    assert rules[0]["properties"]["cwe"] == ["CWE-601"]


def test_build_sarif_result_fields():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    result = sarif["runs"][0]["results"][0]
    assert result["ruleId"] == "CVE-2023-41080"
    assert result["level"] == "warning"
    assert "(Moderate)" in result["message"]["text"]
    assert "CVE-2023-41080" in result["message"]["text"]


def test_build_sarif_region():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    region = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
    assert region["startLine"] == 755
    assert region["endLine"] == 757
    assert region["startColumn"] == 1
    assert region["endColumn"] == 80
    assert isinstance(region["startLine"], int)
    assert isinstance(region["endLine"], int)
    assert isinstance(region["startColumn"], int)
    assert isinstance(region["endColumn"], int)
    assert "protected String savedRequestURL" in region["snippet"]["text"]


def test_build_sarif_artifact_uri():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    uri = sarif["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]["uri"]
    assert uri == "java/org/apache/catalina/authenticator/FormAuthenticator.java"


def test_build_sarif_properties():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["cve"] == "CVE-2023-41080"
    assert props["patch_complexity_score"] == 1
    assert props["files_touched"] == 1
    assert isinstance(props["patch_complexity_score"], int)
    assert isinstance(props["files_touched"], int)


def test_build_sarif_level_low():
    low_cve = {
        **_MODERATE_CVE,
        "cve_id": "CVE-2026-24880",
        "severity": "Low",
        "d1_score": 3,
        "all_methods": ["parseChunkHeader()"],
    }
    sarif = build_sarif(low_cve, start_line=365, end_line=412)
    result = sarif["runs"][0]["results"][0]
    assert result["level"] == "note"
    assert "(Low)" in result["message"]["text"]


def test_build_sarif_message_multi_method():
    multi_cve = {
        **_MODERATE_CVE,
        "cve_id": "CVE-2026-34483",
        "cwe_id": "CWE-117",
        "cwe_description": "Improper Output Neutralization for Logs",
        "severity": "Low",
        "d1_score": 1,
        "grep_term": "RequestElement",
        "is_class": True,
        "all_methods": ["RequestElement.addElement()", "RequestURIElement.addElement()"],
    }
    sarif = build_sarif(multi_cve, start_line=1343, end_line=1344)
    msg = sarif["runs"][0]["results"][0]["message"]["text"]
    assert "RequestElement.addElement()" in msg
    assert "RequestURIElement.addElement()" in msg


def test_build_sarif_rule_id_matches_result_rule_id():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    rule_id = sarif["runs"][0]["tool"]["driver"]["rules"][0]["id"]
    result_rule_id = sarif["runs"][0]["results"][0]["ruleId"]
    assert rule_id == result_rule_id


def test_main_creates_sarif_files(tmp_path):
    sarif_dir = tmp_path / "sarif"
    main(fixes_dir=Path("fixes"), sarif_dir=sarif_dir, tomcat_dir=Path("tomcat"))
    sarif_files = sorted(sarif_dir.glob("CVE-*.sarif"))
    # Derive expected CVE IDs from fix markdown filenames (strip _before_after suffix)
    expected = {p.stem.replace("_before_after", "") for p in Path("fixes").glob("CVE-*_before_after.md")}
    assert {f.stem for f in sarif_files} == expected


def test_main_sarif_files_are_valid(tmp_path):
    sarif_dir = tmp_path / "sarif"
    main(fixes_dir=Path("fixes"), sarif_dir=sarif_dir, tomcat_dir=Path("tomcat"))
    for sarif_file in sarif_dir.glob("CVE-*.sarif"):
        sarif = json.loads(sarif_file.read_text(encoding="utf-8"))
        assert sarif["version"] == "2.1.0"
        run = sarif["runs"][0]
        assert run["tool"]["driver"]["name"] == "tomcat-cve-benchmark"
        result = run["results"][0]
        assert result["level"] in ("note", "warning", "error")
        # startLine falls back to 1 when tomcat/ source is absent (gitignored).
        # Line number quality is validated against the real source tree locally.
        assert result["locations"][0]["physicalLocation"]["region"]["startLine"] >= 1


def test_main_creates_sarif_dir_if_missing(tmp_path):
    sarif_dir = tmp_path / "nested" / "sarif"
    assert not sarif_dir.exists()
    main(fixes_dir=Path("fixes"), sarif_dir=sarif_dir, tomcat_dir=Path("tomcat"))
    assert sarif_dir.exists()
    expected_count = len(list(Path("fixes").glob("CVE-*_before_after.md")))
    assert len(list(sarif_dir.glob("CVE-*.sarif"))) == expected_count


# --- _clean_before_lines unit tests ---

def test_clean_before_lines_strips_arrow_annotation():
    lines = [
        "    buf.append(request.getRequestURI());          // ← unescaped",
        "    buf.append(request.getMethod());",
    ]
    result = _clean_before_lines(lines, is_class=False)
    assert "←" not in "\n".join(result)
    assert "buf.append(request.getRequestURI());" in result[0]


def test_clean_before_lines_removes_truncation_marker():
    lines = [
        "    some code",
        "    // ... remainder unchanged",
        "    more code",
    ]
    result = _clean_before_lines(lines, is_class=False)
    assert len(result) == 2
    for line in result:
        assert not re.match(r"\s*//\s*\.\.\.", line)


def test_clean_before_lines_trims_to_first_brace_block():
    lines = [
        "/** Javadoc */",
        "class RequestElement implements X {",
        "    void foo() {}",
        "}",
        "",
        "/** Second */",
        "class RequestURIElement implements X {",
        "    void bar() {}",
        "}",
    ]
    result = _clean_before_lines(lines, is_class=True)
    assert len(result) == 4
    assert "RequestURIElement" not in "\n".join(result)


def test_clean_before_lines_no_trim_when_not_class():
    lines = ["line1 {", "line2", "}", "line3 {", "}"]
    result = _clean_before_lines(lines, is_class=False)
    assert len(result) == 5


def test_clean_before_lines_brace_mismatch_fallback():
    lines = ["class Foo {", "    code", "// no closing brace"]
    result = _clean_before_lines(lines, is_class=True)
    assert result == lines


# --- parse_markdown integration tests ---

def test_parse_markdown_no_request_uri_element_in_snippet():
    data = parse_markdown(Path("fixes/CVE-2026-34483_before_after.md"))
    assert "RequestURIElement" not in "\n".join(data["before_lines"])


def test_parse_markdown_no_annotations_in_before_lines():
    for md in [
        "CVE-2023-41080_before_after.md",
        "CVE-2026-24880_before_after.md",
        "CVE-2026-34483_before_after.md",
    ]:
        data = parse_markdown(Path(f"fixes/{md}"))
        joined = "\n".join(data["before_lines"])
        assert "←" not in joined, f"{md}: found ← in before_lines"
        for line in data["before_lines"]:
            assert not re.match(r"\s*//\s*\.\.\.", line), f"{md}: found truncation marker"


def test_parse_markdown_fix_commits_single():
    data = parse_markdown(Path("fixes/CVE-2023-41080_before_after.md"))
    assert data["fix_commits"] == ["e3703c9a"]


def test_parse_markdown_fix_commits_multiple():
    data = parse_markdown(Path("fixes/CVE-2026-24880_before_after.md"))
    assert data["fix_commits"] == ["fde1a823", "2cb06c34"]


# --- build_sarif fix_commits tests ---

def test_build_sarif_fix_commits_present():
    cve = {**_MODERATE_CVE, "fix_commits": ["abc1234"]}
    sarif = build_sarif(cve, start_line=755, end_line=757)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert props["fix_commits"] == ["abc1234"]


def test_build_sarif_fix_commits_omitted_when_empty():
    cve = {**_MODERATE_CVE, "fix_commits": []}
    sarif = build_sarif(cve, start_line=755, end_line=757)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "fix_commits" not in props


def test_build_sarif_fix_commits_omitted_when_absent():
    sarif = build_sarif(_MODERATE_CVE, start_line=755, end_line=757)
    props = sarif["runs"][0]["results"][0]["properties"]
    assert "fix_commits" not in props
