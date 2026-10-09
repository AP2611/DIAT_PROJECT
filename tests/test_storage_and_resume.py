from __future__ import annotations

from pathlib import Path

from vulntriage.benchmark import run_benchmark
from vulntriage.config import Settings
from vulntriage.storage import ExperimentStore, export_predictions_jsonl, make_cache_key


def _settings(tmp_path: Path) -> Settings:
    settings = Settings()
    settings.paths.sqlite_path = str(tmp_path / "exp.sqlite")
    settings.paths.results_dir = str(tmp_path / "results")
    settings.paths.benchmark_dir = str(tmp_path)
    settings.semgrep.config = str(Path("configs/semgrep.yml"))
    return settings


def test_sqlite_and_export(tmp_path: Path):
    store = ExperimentStore(tmp_path / "db.sqlite")
    store.create_run("abc", {"config_name": "llm_only", "model_name": "mistral"})
    pid = store.insert_prediction(
        {
            "run_id": "abc",
            "sample_id": "s1",
            "config_name": "llm_only",
            "cache_key": "k1",
            "status": "success",
            "ground_truth_label": 1,
            "predicted_label": "vulnerable",
            "p_vulnerable": 0.7,
        }
    )
    assert pid >= 1
    rows = store.predictions_for_run("abc")
    assert rows[0]["sample_id"] == "s1"
    export = tmp_path / "out.jsonl"
    export_predictions_jsonl(rows, export)
    assert export.read_text().strip()
    store.close()


def test_resume_skips_completed(tmp_path: Path, sample_vuln, sample_benign, fake_ollama):
    from vulntriage.dataset import write_jsonl

    ds = tmp_path / "canonical.jsonl"
    write_jsonl([sample_vuln, sample_benign], ds)
    settings = _settings(tmp_path)

    first = run_benchmark(
        configs=["llm_only"],
        dataset_path=ds,
        limit=2,
        include_synthetic=True,
        settings=settings,
        client=fake_ollama,  # type: ignore[arg-type]
        reuse_cache=False,
    )
    assert fake_ollama.calls == 2
    run_id = first["run_ids"][0]
    # Interrupt simulation: delete second prediction
    store = ExperimentStore(tmp_path / "exp.sqlite")
    store._conn.execute(
        "DELETE FROM predictions WHERE run_id = ? AND sample_id = ?",
        (run_id, sample_benign.sample_id),
    )
    store._conn.commit()
    store.close()
    calls_before = fake_ollama.calls
    run_benchmark(
        configs=["llm_only"],
        dataset_path=ds,
        limit=2,
        include_synthetic=True,
        settings=settings,
        client=fake_ollama,  # type: ignore[arg-type]
        resume_run_id=run_id,
        reuse_cache=False,
    )
    assert fake_ollama.calls == calls_before + 1
    store = ExperimentStore(tmp_path / "exp.sqlite")
    ids = store.existing_sample_ids(run_id)
    store.close()
    assert sample_vuln.sample_id in ids
    assert sample_benign.sample_id in ids


def test_cache_key_changes_with_config():
    kwargs = dict(
        sample_id="s",
        code="x",
        model_name="mistral",
        prompt_version="v1",
        generation_settings={"temperature": 0},
        embedding_model=None,
        index_version=None,
        semgrep_config=None,
        decision_threshold=0.5,
    )
    a = make_cache_key(config_name="llm_only", **kwargs)
    b = make_cache_key(config_name="llm_sast", **kwargs)
    assert a != b
