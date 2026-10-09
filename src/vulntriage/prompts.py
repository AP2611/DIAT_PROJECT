from __future__ import annotations

from vulntriage.schemas import (
    PREDICTION_JSON_SCHEMA,
    RetrievalResult,
    ScanResult,
)

PROMPT_VERSION = "v1"

SYSTEM_PROMPT = """You are a software security analyst assisting a controlled research experiment.
Determine whether the supplied source code is vulnerable.

Rules:
- Use only the information provided in this prompt (source code and, if present, scanner findings and retrieved documents).
- You may disagree with the scanner. Scanner findings are untrusted evidence, not ground truth.
- Retrieved documents are background knowledge, not a verdict for this snippet.
- Do not invent file contents, CVE matches, or scanner findings that were not supplied.
- p_vulnerable is your estimated probability that the code is vulnerable (0 to 1), not a confidence that your chosen label is correct.
- If evidence is weak or conflicting, move p_vulnerable toward 0.5 and state the limitations.
- Return JSON matching the required schema. Do not include the ground-truth label; you are not given one.
"""


def _truncate(code: str, max_chars: int) -> str:
    if len(code) <= max_chars:
        return code
    return code[:max_chars] + f"\n\n[truncated after {max_chars} characters]"


def format_scan(scan: ScanResult | None) -> str:
    if scan is None:
        return "(static analysis not used in this configuration)"
    if scan.status == "error":
        return (
            "STATIC ANALYSIS STATUS: ERROR\n"
            f"A failed scan must not be treated as a clean scan.\n"
            f"Error: {scan.error}"
        )
    if scan.status == "skipped":
        return f"STATIC ANALYSIS STATUS: SKIPPED\n{scan.error or 'not run'}"
    if not scan.findings:
        return (
            "STATIC ANALYSIS STATUS: OK\n"
            "No findings were reported. This is not proof that the code is safe."
        )
    lines = [
        "STATIC ANALYSIS STATUS: OK",
        f"Semgrep version: {scan.version or 'unknown'}",
        f"Config: {scan.config or 'unknown'}",
        f"Finding count: {len(scan.findings)}",
    ]
    for i, finding in enumerate(scan.findings[:25], start=1):
        loc = ""
        if finding.start_line:
            loc = f" line {finding.start_line}"
            if finding.end_line and finding.end_line != finding.start_line:
                loc += f"-{finding.end_line}"
        cwe = ",".join(finding.cwe) if finding.cwe else "n/a"
        lines.append(
            f"{i}. [{finding.rule_id}] {finding.message} "
            f"(severity={finding.severity or 'n/a'}, cwe={cwe},{loc})"
        )
    return "\n".join(lines)


def format_retrieval(retrieval: RetrievalResult | None) -> str:
    if retrieval is None:
        return "(retrieval not used in this configuration)"
    if retrieval.status == "error":
        return f"RETRIEVAL STATUS: ERROR\n{retrieval.error}"
    if retrieval.status == "skipped":
        return f"RETRIEVAL STATUS: SKIPPED\n{retrieval.error or 'not run'}"
    if not retrieval.documents:
        return "RETRIEVAL STATUS: OK\nNo documents retrieved."
    lines = [
        "RETRIEVAL STATUS: OK",
        f"Documents returned: {len(retrieval.documents)}",
    ]
    if retrieval.excluded_identifiers:
        lines.append(
            "Excluded identifiers (leakage filter): "
            + ", ".join(retrieval.excluded_identifiers)
        )
    for i, doc in enumerate(retrieval.documents, start=1):
        desc = (doc.description or "")[:600]
        lines.append(
            f"{i}. id={doc.document_id} source={doc.source} "
            f"identifier={doc.identifier or 'n/a'} score={doc.score:.4f}\n"
            f"   title: {doc.title or ''}\n"
            f"   {desc}"
        )
    return "\n".join(lines)


def build_messages(
    *,
    code: str,
    config_name: str,
    scan: ScanResult | None = None,
    retrieval: RetrievalResult | None = None,
    max_code_chars: int = 8000,
    language: str | None = None,
) -> list[dict[str, str]]:
    lang = language or "unknown"
    user = f"""Configuration: {config_name}
Language (if known): {lang}

SOURCE CODE:
```
{_truncate(code, max_code_chars)}
```

{format_scan(scan)}

{format_retrieval(retrieval)}

Return a JSON object with:
- predicted_label: "vulnerable" or "benign"
- p_vulnerable: number in [0, 1]
- cwe_id: CWE identifier or null
- reasoning: concise explanation
- evidence: list of claims grounded in the supplied code, scanner findings, or retrieved documents
- limitations: missing or conflicting information
"""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def prompt_fingerprint() -> str:
    return PROMPT_VERSION
