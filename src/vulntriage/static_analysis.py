from __future__ import annotations

import json
import shutil
import subprocess
import tempfile
from pathlib import Path
from typing import Any

from vulntriage.schemas import ScanResult, SemgrepFinding


def semgrep_version(executable: str | None = None) -> str | None:
    binary = executable or shutil.which("semgrep")
    if not binary:
        return None
    try:
        proc = subprocess.run(
            [binary, "--version"],
            check=False,
            capture_output=True,
            text=True,
            timeout=15,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (proc.stdout or proc.stderr or "").strip()
    return text.splitlines()[0] if text else None


def _extract_cwes(metadata: dict[str, Any] | None) -> list[str]:
    if not metadata:
        return []
    raw = metadata.get("cwe") or metadata.get("cwe_id") or []
    if isinstance(raw, str):
        raw = [raw]
    out: list[str] = []
    for item in raw:
        text = str(item).strip()
        if not text:
            continue
        if text.startswith("CWE-"):
            out.append(text.split(":")[0].split(" ")[0])
        elif text.isdigit():
            out.append(f"CWE-{text}")
        else:
            out.append(text)
    return out


def parse_semgrep_json(payload: dict[str, Any], *, config: str | None = None) -> ScanResult:
    findings: list[SemgrepFinding] = []
    for item in payload.get("results") or []:
        extra = item.get("extra") or {}
        metadata = extra.get("metadata") or {}
        start = item.get("start") or {}
        end = item.get("end") or {}
        findings.append(
            SemgrepFinding(
                rule_id=item.get("check_id") or extra.get("fingerprint") or "unknown",
                message=extra.get("message") or item.get("message") or "",
                severity=extra.get("severity"),
                path=item.get("path"),
                start_line=start.get("line"),
                end_line=end.get("line"),
                start_col=start.get("col"),
                cwe=_extract_cwes(metadata),
                extra={"metadata": metadata} if metadata else {},
            )
        )
    errors = payload.get("errors") or []
    status = "ok"
    error_text = None
    if errors and not findings:
        # Semgrep can return partial results; only mark error if it reported errors.
        # Still keep status ok if there are findings. If only errors, treat as error.
        status = "error"
        error_text = json.dumps(errors[:3])[:1000]
    return ScanResult(
        status=status if not error_text else "error",
        findings=findings,
        version=(payload.get("version") or None),
        config=config,
        error=error_text,
        raw={"n_results": len(findings), "n_errors": len(errors)},
    )


def scan_code(
    code: str,
    *,
    config: str | Path,
    language_hint: str | None = None,
    timeout_seconds: float = 60.0,
    executable: str | None = None,
) -> ScanResult:
    binary = executable or shutil.which("semgrep")
    config_path = str(config)
    if not binary:
        return ScanResult(
            status="error",
            findings=[],
            config=config_path,
            error="semgrep executable not found on PATH",
        )
    suffix = ".py"
    hint = (language_hint or "").lower()
    if hint in {"javascript", "js"}:
        suffix = ".js"
    elif hint in {"c", "cpp", "c++"}:
        suffix = ".c"
    elif hint in {"java"}:
        suffix = ".java"
    elif hint in {"go"}:
        suffix = ".go"
    with tempfile.TemporaryDirectory(prefix="vulntriage-semgrep-") as tmp:
        target = Path(tmp) / f"sample{suffix}"
        target.write_text(code, encoding="utf-8")
        cmd = [
            binary,
            "scan",
            "--json",
            "--quiet",
            "--config",
            config_path,
            str(target),
        ]
        try:
            proc = subprocess.run(
                cmd,
                check=False,
                capture_output=True,
                text=True,
                timeout=timeout_seconds,
            )
        except subprocess.TimeoutExpired as exc:
            return ScanResult(
                status="error",
                config=config_path,
                version=semgrep_version(binary),
                error=f"semgrep timed out after {timeout_seconds}s: {exc}",
            )
        except OSError as exc:
            return ScanResult(
                status="error",
                config=config_path,
                error=f"failed to launch semgrep: {exc}",
            )
        stdout = proc.stdout.strip()
        if not stdout:
            return ScanResult(
                status="error",
                config=config_path,
                version=semgrep_version(binary),
                error=(
                    f"semgrep produced no JSON (exit {proc.returncode}). "
                    f"stderr: {(proc.stderr or '')[:800]}"
                ),
            )
        try:
            payload = json.loads(stdout)
        except json.JSONDecodeError as exc:
            return ScanResult(
                status="error",
                config=config_path,
                version=semgrep_version(binary),
                error=f"semgrep JSON parse failed: {exc}; stdout={stdout[:400]}",
            )
        result = parse_semgrep_json(payload, config=config_path)
        result.version = payload.get("version") or semgrep_version(binary)
        if proc.returncode not in {0, 1} and result.status == "ok" and not result.findings:
            # 0 = clean, 1 = findings; other codes are failures.
            result.status = "error"
            result.error = (
                f"semgrep exit {proc.returncode}: {(proc.stderr or '')[:800]}"
            )
        return result
