from __future__ import annotations

from vulntriage.static_analysis import parse_semgrep_json, scan_code


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
