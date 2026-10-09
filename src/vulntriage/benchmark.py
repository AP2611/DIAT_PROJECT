from __future__ import annotations

import json
import subprocess
import uuid
from pathlib import Path
from typing import Any, Callable, Sequence

from vulntriage.config import ROOT, Settings, load_settings
from vulntriage.dataset import load_jsonl, select_pilot, write_jsonl
from vulntriage.experiments import ExperimentContext, USES_RAG, USES_SAST, run_sample
from vulntriage.metrics import comparison_table, summarize_run
from vulntriage.ollama_client import OllamaClient
from vulntriage.prompts import PROMPT_VERSION
from vulntriage.retrieval import VectorIndex, code_query
from vulntriage.schemas import CanonicalSample, RetrievalResult
from vulntriage.static_analysis import semgrep_version
from vulntriage.storage import ExperimentStore, export_predictions_csv, export_predictions_jsonl

ALL_CONFIGS = ("llm_only", "llm_sast", "llm_rag", "llm_sast_rag")


def git_commit() -> str | None:
    try:
        proc = subprocess.run(
            ["git", "rev-parse", "HEAD"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    if proc.returncode != 0:
        return None
    return proc.stdout.strip() or None


def default_dataset_path(settings: Settings) -> Path:
    processed = settings.resolve(settings.paths.benchmark_dir) / "canonical.jsonl"
    if processed.exists():
        return processed
    return ROOT / "data" / "benchmark" / "synthetic_smoke.jsonl"


def load_samples(
    path: Path,
    *,
    limit: int | None,
    seed: int,
    split: str | None,
    include_synthetic: bool,
) -> list[CanonicalSample]:
    samples = load_jsonl(path)
    if limit is None:
        if not include_synthetic:
            return [s for s in samples if not s.is_synthetic] or samples
        return samples
    return select_pilot(
        samples,
        limit=limit,
        seed=seed,
        split=split,
        include_synthetic=include_synthetic,
    )


def _retriever_factory(
    settings: Settings,
    embedder_factory: Callable[[], Any] | None = None,
) -> tuple[Callable[[CanonicalSample], RetrievalResult] | None, str | None, str | None]:
    qpath = settings.resolve(settings.paths.qdrant_path)
    meta_path = qpath / "index_meta.json"
    if not meta_path.exists():
        return None, None, None
    meta = json.loads(meta_path.read_text())
    if embedder_factory is None:
        from vulntriage.embeddings import load_embedder

        embedder = load_embedder(
            settings.embeddings.model_name, device=settings.embeddings.device
        )
    else:
        embedder = embedder_factory()
    index = VectorIndex(qpath, settings.embeddings.collection_name, embedder)

    def retrieve(sample: CanonicalSample) -> RetrievalResult:
        excluded = []
        if sample.cve_id:
            excluded.append(sample.cve_id)
        return index.search(
            code_query(sample.code),
            top_k=settings.embeddings.top_k,
            exclude_identifiers=excluded,
        )

    return retrieve, meta.get("index_version"), embedder.model_name


def run_benchmark(
    *,
    configs: Sequence[str],
    dataset_path: Path | None = None,
    limit: int | None = 20,
    seed: int | None = None,
    split: str | None = None,
    include_synthetic: bool = False,
    resume_run_id: str | None = None,
    force: bool = False,
    reuse_cache: bool = True,
    settings: Settings | None = None,
    client: OllamaClient | None = None,
    retriever: Callable[[CanonicalSample], RetrievalResult] | None = None,
    embedder_factory: Callable[[], Any] | None = None,
    notes: str | None = None,
) -> dict[str, Any]:
    settings = settings or load_settings()
    seed = settings.default_seed if seed is None else seed
    path = dataset_path or default_dataset_path(settings)
    samples = load_samples(
        path,
        limit=limit,
        seed=seed,
        split=split,
        include_synthetic=include_synthetic,
    )
    if not samples:
        raise RuntimeError(f"No samples loaded from {path}")

    ollama = client or OllamaClient(
        url=settings.ollama.url,
        model=settings.ollama.model,
        temperature=settings.ollama.temperature,
        num_ctx=settings.ollama.num_ctx,
        num_predict=settings.ollama.num_predict,
        timeout_seconds=settings.ollama.timeout_seconds,
        use_json_schema=settings.ollama.use_json_schema,
    )
    model_digest = None
    try:
        health = ollama.health()
        model_digest = str(
            (health.get("model_details") or {}).get("digest")
            or health.get("version")
        )
    except Exception:
        health = None

    retrieve_fn = retriever
    index_version = None
    embedding_model = None
    if retriever is None and any(c in USES_RAG for c in configs):
        retrieve_fn, index_version, embedding_model = _retriever_factory(
            settings, embedder_factory=embedder_factory
        )

    store = ExperimentStore(settings.resolve(settings.paths.sqlite_path))
    run_ids: list[str] = []
    summaries: dict[str, Any] = {}
    try:
        for config_name in configs:
            if config_name not in ALL_CONFIGS:
                raise ValueError(f"Unknown config {config_name}; expected one of {ALL_CONFIGS}")
            if resume_run_id and len(configs) == 1:
                run_id = resume_run_id
                if not store.get_run(run_id):
                    raise RuntimeError(f"Unknown run_id {run_id}")
            else:
                run_id = uuid.uuid4().hex[:12]
                store.create_run(
                    run_id,
                    {
                        "config_name": config_name,
                        "dataset_name": path.name,
                        "dataset_version": str(path),
                        "model_name": ollama.model,
                        "model_digest": model_digest,
                        "prompt_version": PROMPT_VERSION,
                        "embedding_model": embedding_model if config_name in USES_RAG else None,
                        "index_version": index_version if config_name in USES_RAG else None,
                        "semgrep_version": semgrep_version() if config_name in USES_SAST else None,
                        "semgrep_config": settings.semgrep.config if config_name in USES_SAST else None,
                        "generation_settings": {
                            "temperature": ollama.temperature,
                            "num_ctx": ollama.num_ctx,
                            "num_predict": ollama.num_predict,
                            "use_json_schema": ollama.use_json_schema,
                            "threshold": settings.decision_threshold,
                            "seed": seed,
                            "limit": limit,
                        },
                        "decision_threshold": settings.decision_threshold,
                        "git_commit": git_commit(),
                        "notes": notes,
                    },
                )
            run_ids.append(run_id)
            already = store.existing_sample_ids(run_id)
            ctx = ExperimentContext(
                config_name=config_name,
                client=ollama,
                decision_threshold=settings.decision_threshold,
                max_code_chars=settings.max_code_chars,
                semgrep_config=str(settings.resolve(settings.semgrep.config)),
                semgrep_timeout=settings.semgrep.timeout_seconds,
                retrieve=retrieve_fn,
                index_version=index_version,
                embedding_model=embedding_model,
            )
            if config_name in USES_RAG and retrieve_fn is None:
                # Still run: each sample records retrieval error rather than dropping.
                pass
            for sample in samples:
                if sample.sample_id in already and not force:
                    continue
                # Placeholder record to compute cache key via run_sample only when needed.
                if reuse_cache and not force:
                    # Peek cache using a dry key by running the same key function inside run_sample
                    # after execution; we also check after constructing via a light call:
                    from vulntriage.storage import make_cache_key

                    generation_settings = {
                        "temperature": ollama.temperature,
                        "num_ctx": ollama.num_ctx,
                        "num_predict": ollama.num_predict,
                        "use_json_schema": ollama.use_json_schema,
                    }
                    cache_key = make_cache_key(
                        sample_id=sample.sample_id,
                        code=sample.code,
                        config_name=config_name,
                        model_name=ollama.model,
                        prompt_version=PROMPT_VERSION,
                        generation_settings=generation_settings,
                        embedding_model=embedding_model if config_name in USES_RAG else None,
                        index_version=index_version if config_name in USES_RAG else None,
                        semgrep_config=settings.semgrep.config if config_name in USES_SAST else None,
                        decision_threshold=settings.decision_threshold,
                    )
                    cached = store.find_cached(cache_key)
                    if cached:
                        copy = dict(cached)
                        copy.pop("id", None)
                        copy["run_id"] = run_id
                        copy["reused_from"] = cached.get("id")
                        copy["created_at"] = None
                        try:
                            store.insert_prediction(copy)
                            continue
                        except Exception:
                            pass
                record = run_sample(sample, ctx)
                record["run_id"] = run_id
                store.insert_prediction(record)
            rows = store.predictions_for_run(run_id)
            summary = summarize_run(rows, include_synthetic=include_synthetic)
            store.save_metrics(run_id, config_name, summary)
            store.finish_run(run_id, "completed")
            summaries[config_name] = {"run_id": run_id, **summary}
    finally:
        store.close()

    return {
        "run_ids": run_ids,
        "dataset": str(path),
        "n_samples": len(samples),
        "sample_ids": [s.sample_id for s in samples],
        "configs": list(configs),
        "summaries": summaries,
        "comparison": comparison_table(
            {k: v for k, v in summaries.items()}
        ),
        "include_synthetic": include_synthetic,
        "health": {k: health.get(k) for k in ("reachable", "configured_model", "model_names")}
        if isinstance(health, dict)
        else None,
    }


def export_run(run_id: str | None = None, settings: Settings | None = None) -> dict[str, Path]:
    settings = settings or load_settings()
    store = ExperimentStore(settings.resolve(settings.paths.sqlite_path))
    try:
        rid = run_id or store.latest_run_id()
        if not rid:
            raise RuntimeError("No runs to export")
        rows = store.predictions_for_run(rid)
        metrics = store.latest_metrics(rid)
        export_dir = settings.resolve(settings.paths.results_dir) / "exports"
        jsonl_path = export_dir / f"{rid}.jsonl"
        csv_path = export_dir / f"{rid}.csv"
        metrics_path = export_dir / f"{rid}.metrics.json"
        export_predictions_jsonl(rows, jsonl_path)
        export_predictions_csv(rows, csv_path)
        metrics_path.write_text(json.dumps(metrics, indent=2, default=str))
        return {"jsonl": jsonl_path, "csv": csv_path, "metrics": metrics_path, "run_id": Path(rid)}
    finally:
        store.close()
