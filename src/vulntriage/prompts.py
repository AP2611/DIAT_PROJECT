from __future__ import annotations

from vulntriage.schemas import (
    PREDICTION_JSON_SCHEMA,
    RetrievalResult,
    ScanResult,
)

PROMPT_VERSION = "v3"

SYSTEM_PROMPT = """You are a software security analyst assisting a controlled research experiment.
Determine whether the supplied source code contains a security vulnerability.

Probability semantics (important):
- p_vulnerable is your estimated probability that THIS code contains a real, exploitable
  security flaw. It is NOT a confidence in a label you chose first.
- Do not output a separate predicted_label. Only p_vulnerable determines the decision.
- 0.5 means complete uncertainty. Use 0.2-0.4 for plausible but unconfirmed concerns,
  0.6-0.8 for a concrete flaw pattern, and 0.85-0.95 for a clear exploitable flaw.
- Do not collapse to 0.1 just because you did not immediately see a vulnerability.
  Lack of evidence is not evidence of safety. If you are unsure, stay near 0.5.

Evidence rules:
- Use the supplied code and your general knowledge of secure coding and common CWE
  patterns. Do not invent file contents, CVE matches, or scanner findings that were
  not supplied.
- Scanner findings, when present, are untrusted hints. You may disagree with them.
- An empty scanner result is weak evidence only. It must not, by itself, lower
  p_vulnerable: the scanner may simply not cover this language or bug class.
- Retrieved documents are background knowledge, not a verdict for this snippet.
- State limitations, but do not use them as a reason to default to "benign".

Worked example (format only, not this task):
Code: a C function that copies strcpy(dest, user_input) into char dest[16].
Output: {"p_vulnerable":0.9,"cwe_id":"CWE-120","reasoning":"strcpy copies unbounded input into a 16-byte buffer.","evidence":["strcpy(dest, user_input) with fixed-size dest"],"limitations":"Caller constraints unknown"}

Return a JSON object matching the required schema. Do not include the ground-truth
label; you are not given one.
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
            "A failed scan must not be treated as a clean scan.\n"
            f"Error: {scan.error}"
        )
    if scan.status == "skipped":
        return f"STATIC ANALYSIS STATUS: SKIPPED\n{scan.error or 'not run'}"
    if not scan.findings:
        return (
            "STATIC ANALYSIS STATUS: OK - no findings reported.\n"
            "This is weak evidence only. The ruleset may not cover this language "
            "or bug class. Do not lower p_vulnerable because of an empty scan; "
            "base your probability on the code itself."
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
    user = f"""Language (if known): {lang}

SOURCE CODE:
```
{_truncate(code, max_code_chars)}
```

{format_scan(scan)}

{format_retrieval(retrieval)}

Return a JSON object with these fields only:
- p_vulnerable: number in [0, 1], your estimated probability this code is vulnerable
- cwe_id: CWE identifier or null
- reasoning: concise explanation of the concrete code evidence
- evidence: list of claims grounded in the supplied code, scanner findings, or retrieved documents
- limitations: missing or conflicting information

Do not output a predicted_label field; the decision is derived from p_vulnerable.
"""
    return [
        {"role": "system", "content": SYSTEM_PROMPT},
        {"role": "user", "content": user},
    ]


def prompt_fingerprint() -> str:
    return PROMPT_VERSION
