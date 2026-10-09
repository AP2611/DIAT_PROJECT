from __future__ import annotations

from pathlib import Path

from vulntriage.benchmark import run_benchmark
from vulntriage.config import Settings
from vulntriage.dataset import write_jsonl
from vulntriage.experiments import ExperimentContext, run_sample
from vulntriage.retrieval import RetrievalResult, RetrievedDocument
from vulntriage.schemas import CanonicalSample


class RecordingOllama:
    def __init__(self) -> None:
        from tests.fakes import FakeOllama

        self.inner = FakeOllama(p=0.2)
        self.model = self.inner.model
        self.temperature = 0.0
        self.num_ctx = 1024
        self.num_predict = 64
        self.use_json_schema = True

    def chat(self, messages, format_schema=None):
        blob = str(messages)
        assert "ground_truth" not in blob.lower()
        assert "'label': 1" not in blob
        assert '"label": 1' not in blob
        return self.inner.chat(messages, format_schema=format_schema)


def test_prompt_omits_ground_truth(sample_vuln: CanonicalSample):
    client = RecordingOllama()
    ctx = ExperimentContext(config_name="llm_only", client=client)  # type: ignore[arg-type]
    record = run_sample(sample_vuln, ctx)
    assert record["status"] == "success"
    assert record["ground_truth_label"] == 1
    assert record["predicted_label"] == "benign"  # p=0.2
    prompt = record["prompt_json"]
    assert "ground_truth" not in prompt


def test_four_configs_end_to_end(tmp_path: Path, sample_vuln, sample_benign, monkeypatch):
    ds = tmp_path / "canonical.jsonl"
    write_jsonl([sample_vuln, sample_benign], ds)
    settings = Settings()
    settings.paths.sqlite_path = str(tmp_path / "exp.sqlite")
    settings.paths.results_dir = str(tmp_path / "results")
    settings.semgrep.config = str(Path("configs/semgrep.yml"))

    def fake_scan(code, **kwargs):
        from vulntriage.schemas import ScanResult

        return ScanResult(status="ok", findings=[], version="stub", config=str(kwargs.get("config")))

    monkeypatch.setattr("vulntriage.experiments.scan_code", fake_scan)

    def retrieve(sample):
        return RetrievalResult(
            status="ok",
            documents=[
                RetrievedDocument(
                    document_id="cwe:CWE-89",
                    score=0.9,
                    source="CWE",
                    identifier="CWE-89",
                    title="SQL Injection",
                    description="...",
                )
            ],
            excluded_identifiers=[sample.cve_id] if sample.cve_id else [],
        )

    from tests.fakes import FakeOllama

    client = FakeOllama(p=0.6)
    result = run_benchmark(
        configs=["llm_only", "llm_sast", "llm_rag", "llm_sast_rag"],
        dataset_path=ds,
        limit=2,
        include_synthetic=True,
        settings=settings,
        client=client,  # type: ignore[arg-type]
        retriever=retrieve,
        reuse_cache=False,
    )
    assert set(result["configs"]) == {"llm_only", "llm_sast", "llm_rag", "llm_sast_rag"}
    assert client.calls == 8
    for summary in result["summaries"].values():
        assert summary["n_success"] == 2
        assert summary["n_failed"] == 0
