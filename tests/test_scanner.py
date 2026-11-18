from __future__ import annotations

from vulntriage.static_analysis import _infer_suffix, parse_semgrep_json, scan_code


def test_parse_findings():
    payload = {
        "version": "1.80.0",
        "results": [
            {
                "check_id": "python.sql",
                "path": "sample.py",
                "start": {"line": 3, "col": 1},
                "end": {"line": 3, "col": 10},
                "extra": {
                    "message": "SQL injection",
                    "severity": "ERROR",
                    "metadata": {"cwe": ["CWE-89: SQL Injection"]},
                },
            }
        ],
        "errors": [],
    }
    result = parse_semgrep_json(payload, config="configs/semgrep.yml")
    assert result.status == "ok"
    assert result.findings[0].rule_id == "python.sql"
    assert result.findings[0].start_line == 3
    assert result.findings[0].cwe == ["CWE-89"]


def test_missing_semgrep_is_error_not_clean(monkeypatch):
    monkeypatch.setattr("vulntriage.static_analysis.shutil.which", lambda _: None)
    result = scan_code("print(1)", config="configs/semgrep.yml")
    assert result.status == "error"
    assert result.findings == []
    assert "not found" in (result.error or "").lower()


def test_empty_stdout_is_error(monkeypatch):
    class Proc:
        returncode = 2
        stdout = ""
        stderr = "boom"

    monkeypatch.setattr("vulntriage.static_analysis.shutil.which", lambda _: "/usr/bin/semgrep")
    monkeypatch.setattr(
        "vulntriage.static_analysis.subprocess.run",
        lambda *a, **k: Proc(),
    )
    monkeypatch.setattr("vulntriage.static_analysis.semgrep_version", lambda *_: "1.0")
    result = scan_code("print(1)", config="configs/semgrep.yml")
    assert result.status == "error"
    assert "no JSON" in (result.error or "")


def test_infer_suffix_from_language_hint():
    assert _infer_suffix("c") == ".c"
    assert _infer_suffix("cpp") == ".cpp"
    assert _infer_suffix("c++") == ".cpp"
    assert _infer_suffix("javascript") == ".js"
    assert _infer_suffix("js") == ".js"
    assert _infer_suffix("java") == ".java"
    assert _infer_suffix("go") == ".go"
    assert _infer_suffix("python") == ".py"


def test_infer_suffix_from_file_name_when_hint_missing():
    assert _infer_suffix(None, "foo.c") == ".c"
    assert _infer_suffix(None, "foo.cpp") == ".cpp"
    assert _infer_suffix(None, "foo.cc") == ".cpp"
    assert _infer_suffix(None, "foo.py") == ".py"
    assert _infer_suffix(None, "foo.js") == ".js"
    assert _infer_suffix(None, "foo.java") == ".java"
    assert _infer_suffix(None, "foo.go") == ".go"


def test_infer_suffix_defaults_to_c_when_unknown():
    assert _infer_suffix(None, None) == ".c"
    assert _infer_suffix("unknown", None) == ".c"
    assert _infer_suffix(None, "foo.xyz") == ".c"


def test_infer_suffix_language_hint_takes_precedence_over_file_name():
    # A .py file with C language hint should still be .c
    assert _infer_suffix("c", "foo.py") == ".c"
