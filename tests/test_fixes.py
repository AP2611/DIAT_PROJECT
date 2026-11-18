from __future__ import annotations

from pathlib import Path

import pytest

from vulntriage.benchmark import run_benchmark
from vulntriage.config import Settings
from vulntriage.dataset import write_jsonl
from vulntriage.schemas import LLMPrediction, PREDICTION_JSON_SCHEMA


def test_prediction_schema_does_not_ask_for_label():
    assert "predicted_label" not in PREDICTION_JSON_SCHEMA["properties"]
    assert "predicted_label" not in PREDICTION_JSON_SCHEMA["required"]
    parsed = LLMPrediction.model_validate(
        {"p_vulnerable": 0.8, "reasoning": "flaw", "evidence": [], "limitations": "none"}
    )
    assert parsed.predicted_label is None
    assert parsed.derived_label() == "vulnerable"


def test_constant_scores_are_flagged(tmp_path: Path, sample_vuln, sample_benign):
    ds = tmp_path / "canonical.jsonl"
    write_jsonl([sample_vuln, sample_benign], ds)
    settings = Settings(prompt_version="v3")
    settings.paths.sqlite_path = str(tmp_path / "exp.sqlite")
    settings.paths.results_dir = str(tmp_path / "results")

    from tests.fakes import FakeOllama

    result = run_benchmark(
        configs=["llm_only"],
        dataset_path=ds,
        limit=2,
        settings=settings,
        client=FakeOllama(p=0.3),
        reuse_cache=False,
    )
    summary = result["summaries"]["llm_only"]
    assert summary["degenerate_predictions"]["constant_score"] == 0.3
    assert summary["suitable_for_paper"] is False
    assert "not discriminating" in summary["warning"]


def test_rag_without_index_fails_fast(tmp_path: Path, sample_vuln):
    ds = tmp_path / "canonical.jsonl"
    write_jsonl([sample_vuln], ds)
    settings = Settings(prompt_version="v3")
    settings.paths.sqlite_path = str(tmp_path / "exp.sqlite")
    settings.paths.results_dir = str(tmp_path / "results")
    settings.paths.qdrant_path = str(tmp_path / "empty_qdrant")

    from tests.fakes import FakeOllama

    with pytest.raises(RuntimeError, match="no vector index"):
        run_benchmark(
            configs=["llm_rag"],
            dataset_path=ds,
            limit=1,
            settings=settings,
            client=FakeOllama(p=0.5),
            reuse_cache=False,
        )
