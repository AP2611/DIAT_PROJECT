from __future__ import annotations

from pathlib import Path

from vulntriage.config import ROOT

LOG_HEADER = (
    "date,experiment_id,change_made,motivation,result,interpretation,next_step\n"
)

TEMPLATE = """# Experiment observation

Do not fill interpretation as a claim of superiority before results exist.

- Research question: Does combining static-analysis evidence with retrieved cybersecurity knowledge improve vulnerability-detection reliability compared with using either source independently? Can evidence-conditioned decisions also support better confidence calibration?
- Hypothesis: (state before looking at test metrics)
- Run ID:
- Dataset and subset:
- Configuration:
- Number of valid samples:
- Metrics: (paste from `benchmark summarize`; mark uncalibrated)
- Difference from the relevant baseline:
- Observed error patterns:
- Relevant examples (sample IDs):
- Limitations:
- Interpretation:
- Next experiment:
- Suitable for a paper? No — pending a real labelled benchmark run.
"""


def ensure_research_files(research_dir: Path | None = None) -> dict[str, Path]:
    directory = research_dir or (ROOT / "research")
    directory.mkdir(parents=True, exist_ok=True)
    template = directory / "observations_template.md"
    log = directory / "research_log.csv"
    if not template.exists():
        template.write_text(TEMPLATE)
    if not log.exists():
        log.write_text(LOG_HEADER)
    return {"template": template, "log": log}


def append_log_row(
    *,
    date: str,
    experiment_id: str,
    change_made: str,
    motivation: str,
    result: str = "not yet run",
    interpretation: str = "",
    next_step: str = "",
    research_dir: Path | None = None,
) -> Path:
    paths = ensure_research_files(research_dir)
    line = ",".join(
        _csv_cell(x)
        for x in (
            date,
            experiment_id,
            change_made,
            motivation,
            result,
            interpretation,
            next_step,
        )
    )
    with paths["log"].open("a", encoding="utf-8") as handle:
        handle.write(line + "\n")
    return paths["log"]


def _csv_cell(value: str) -> str:
    text = value.replace('"', '""')
    if any(ch in text for ch in ",\n"):
        return f'"{text}"'
    return text
