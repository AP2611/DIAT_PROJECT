from __future__ import annotations

import json
import shutil
from pathlib import Path
from typing import Optional

import typer

from vulntriage import __version__
from vulntriage.benchmark import ALL_CONFIGS, default_dataset_path, export_run, run_benchmark
from vulntriage.config import ROOT, load_settings
from vulntriage.dataset import import_dataset, load_jsonl, select_pilot, write_jsonl
from vulntriage.embeddings import load_embedder
from vulntriage.knowledge_processing import discover_raw_files, load_documents, normalize_knowledge
from vulntriage.metrics import comparison_table, summarize_run
from vulntriage.observations import ensure_research_files
from vulntriage.ollama_client import OllamaClient, OllamaError
from vulntriage.retrieval import VectorIndex, code_query
from vulntriage.static_analysis import semgrep_version
from vulntriage.storage import ExperimentStore

app = typer.Typer(no_args_is_help=True, add_completion=False)
knowledge_app = typer.Typer(no_args_is_help=True)
benchmark_app = typer.Typer(no_args_is_help=True)
app.add_typer(knowledge_app, name="knowledge")
app.add_typer(benchmark_app, name="benchmark")


@app.command()
def doctor(
    config: Optional[Path] = typer.Option(None, "--config", help="YAML config path"),
) -> None:
    """Check Ollama, the configured model, Semgrep, embeddings, and data files."""
    settings = load_settings(config)
    report: dict = {
        "version": __version__,
        "root": str(ROOT),
        "ollama": {},
        "semgrep": {},
        "embeddings": {},
        "knowledge": {},
        "dataset": {},
    }
    client = OllamaClient(
        url=settings.ollama.url,
        model=settings.ollama.model,
        timeout_seconds=10,
    )
    try:
        health = client.health()
        report["ollama"] = {
            "reachable": True,
            "url": settings.ollama.url,
            "version": health.get("version"),
            "configured_model": settings.ollama.model,
            "configured_model_available": health.get("configured_model_available"),
            "model_names": health.get("model_names"),
            "model_details": health.get("model_details"),
        }
        if not health.get("configured_model_available"):
            report["ollama"]["warning"] = (
                f"Configured model {settings.ollama.model!r} was not found. "
                "This prototype will not download a replacement model."
            )
    except OllamaError as exc:
        report["ollama"] = {
            "reachable": False,
            "url": settings.ollama.url,
            "configured_model": settings.ollama.model,
            "error": str(exc),
            "hint": "Start the local daemon: /opt/homebrew/bin/ollama serve",
        }

    binary = shutil.which("semgrep")
    report["semgrep"] = {
        "installed": bool(binary),
        "path": binary,
        "version": semgrep_version(),
        "config": str(settings.resolve(settings.semgrep.config)),
        "config_exists": settings.resolve(settings.semgrep.config).exists(),
    }

    model_name = settings.embeddings.model_name
    cache = Path.home() / ".cache" / "huggingface" / "hub"
    local_dir = cache / ("models--" + model_name.replace("/", "--"))
    report["embeddings"] = {
        "model_name": model_name,
        "huggingface_cache_present": local_dir.exists(),
        "cache_path": str(local_dir),
        "note": (
            "Embeddings run locally via sentence-transformers. "
            "If the model is missing, download it locally; no remote embedding API is used."
        ),
    }

    raw = settings.resolve(settings.paths.raw_data_dir)
    files = discover_raw_files(raw) if raw.exists() else {"nvd": [], "cwe": [], "capec": []}
    report["knowledge"] = {
        "raw_data_dir": str(raw),
        "nvd_files": [p.name for p in files["nvd"]],
        "cwe_files": [str(p) for p in files["cwe"]],
        "capec_files": [str(p) for p in files["capec"]],
        "processed": str(settings.resolve(settings.paths.processed_dir) / "documents.jsonl"),
        "qdrant": str(settings.resolve(settings.paths.qdrant_path)),
        "index_meta_exists": (settings.resolve(settings.paths.qdrant_path) / "index_meta.json").exists(),
    }

    ds = default_dataset_path(settings)
    report["dataset"] = {
        "default_path": str(ds),
        "exists": ds.exists(),
        "note": (
            "No PrimeVul (or other labelled) benchmark is bundled. "
            "Import one with: python -m vulntriage benchmark import --input PATH"
        ),
    }
    typer.echo(json.dumps(report, indent=2, default=str))
    ensure_research_files(settings.resolve(settings.paths.research_dir))
    if not report["ollama"].get("reachable"):
        raise typer.Exit(code=2)
    if not report["ollama"].get("configured_model_available"):
        raise typer.Exit(code=3)


@knowledge_app.command("normalize")
def knowledge_normalize(
    sources: str = typer.Option("nvd,cwe,capec", help="Comma-separated: nvd,cwe,capec"),
    config: Optional[Path] = typer.Option(None, "--config"),
) -> None:
    settings = load_settings(config)
    raw = settings.resolve(settings.paths.raw_data_dir)
    out = settings.resolve(settings.paths.processed_dir) / "documents.jsonl"
    wanted = [s.strip() for s in sources.split(",") if s.strip()]
    counts = normalize_knowledge(raw, out, sources=wanted)
    typer.echo(json.dumps({"output": str(out), **counts}))


@knowledge_app.command("build-index")
def knowledge_build_index(
    config: Optional[Path] = typer.Option(None, "--config"),
    hash_embedder: bool = typer.Option(
        False, help="Use the test hash embedder (not for scientific runs)"
    ),
) -> None:
    settings = load_settings(config)
    docs_path = settings.resolve(settings.paths.processed_dir) / "documents.jsonl"
    if not docs_path.exists():
        raise typer.BadParameter(f"Normalized documents missing: {docs_path}. Run knowledge normalize first.")
    docs = load_documents(docs_path)
    embedder = load_embedder("hash" if hash_embedder else settings.embeddings.model_name)
    index = VectorIndex(
        settings.resolve(settings.paths.qdrant_path),
        settings.embeddings.collection_name,
        embedder,
    )
    meta = index.build(docs, batch_size=settings.embeddings.batch_size)
    typer.echo(json.dumps(meta, indent=2))


@knowledge_app.command("search")
def knowledge_search(
    query: str = typer.Option(..., "--query"),
    top_k: Optional[int] = typer.Option(None, "--top-k"),
    exclude_cve: Optional[str] = typer.Option(None, help="CVE id to drop (leakage filter)"),
    config: Optional[Path] = typer.Option(None, "--config"),
    hash_embedder: bool = typer.Option(False),
) -> None:
    settings = load_settings(config)
    embedder = load_embedder("hash" if hash_embedder else settings.embeddings.model_name)
    index = VectorIndex(
        settings.resolve(settings.paths.qdrant_path),
        settings.embeddings.collection_name,
        embedder,
    )
    result = index.search(
        query if not query.startswith("code:") else code_query(query[5:]),
        top_k=top_k or settings.embeddings.top_k,
        exclude_identifiers=[exclude_cve] if exclude_cve else None,
    )
    typer.echo(result.model_dump_json(indent=2))
    typer.echo(
        "\nRetrieval quality metrics (Precision@k, Recall@k, MRR, nDCG) are not "
        "reported: no relevance judgments are available yet."
    )


@benchmark_app.command("import")
def benchmark_import(
    input: Path = typer.Option(..., "--input", exists=True),
    source: Optional[str] = typer.Option(None, help="Dataset name, e.g. primevul"),
    output: Optional[Path] = typer.Option(None, "--output"),
) -> None:
    settings = load_settings()
    samples, report = import_dataset(input, source_dataset=source)
    out = output or (settings.resolve(settings.paths.benchmark_dir) / "canonical.jsonl")
    write_jsonl(samples, out)
    report["output"] = str(out)
    typer.echo(json.dumps(report, indent=2))


@benchmark_app.command("pilot")
def benchmark_pilot(
    limit: int = typer.Option(20),
    seed: int = typer.Option(42),
    split: Optional[str] = typer.Option(None),
    include_synthetic: bool = typer.Option(False),
    dataset: Optional[Path] = typer.Option(None),
) -> None:
    settings = load_settings()
    src = dataset or default_dataset_path(settings)
    samples = load_jsonl(src)
    chosen = select_pilot(
        samples,
        limit=limit,
        seed=seed,
        split=split,
        include_synthetic=include_synthetic,
    )
    out = settings.resolve(settings.paths.benchmark_dir) / f"pilot_seed{seed}_n{len(chosen)}.jsonl"
    write_jsonl(chosen, out)
    typer.echo(json.dumps({"output": str(out), "n": len(chosen), "ids": [s.sample_id for s in chosen]}, indent=2))


@benchmark_app.command("run")
def benchmark_run(
    config_name: str = typer.Option(
        "llm_only",
        "--config",
        help="llm_only | llm_sast | llm_rag | llm_sast_rag | all",
    ),
    limit: Optional[int] = typer.Option(20, help="Pilot size. Omit large runs accidentally."),
    seed: int = typer.Option(42),
    split: Optional[str] = typer.Option(None),
    dataset: Optional[Path] = typer.Option(None),
    include_synthetic: bool = typer.Option(False, help="Allow synthetic smoke samples"),
    force: bool = typer.Option(False, "--force", help="Do not reuse cached predictions"),
    resume: Optional[str] = typer.Option(None, help="Resume an interrupted run_id"),
    notes: Optional[str] = typer.Option(None),
) -> None:
    if config_name == "all":
        configs = ALL_CONFIGS
    else:
        configs = (config_name,)
    result = run_benchmark(
        configs=configs,
        dataset_path=dataset,
        limit=limit,
        seed=seed,
        split=split,
        include_synthetic=include_synthetic,
        resume_run_id=resume,
        force=force,
        notes=notes,
    )
    typer.echo(json.dumps(result, indent=2, default=str))


@benchmark_app.command("summarize")
def benchmark_summarize(
    latest: bool = typer.Option(False, "--latest"),
    run_id: Optional[str] = typer.Option(None),
    include_synthetic: bool = typer.Option(False),
) -> None:
    settings = load_settings()
    store = ExperimentStore(settings.resolve(settings.paths.sqlite_path))
    try:
        if latest or not run_id:
            runs = store.list_runs(limit=12)
            grouped: dict[str, dict] = {}
            for run in runs:
                rows = store.predictions_for_run(run["run_id"])
                grouped[f"{run['config_name']}:{run['run_id']}"] = summarize_run(
                    rows, include_synthetic=include_synthetic
                )
            payload = {
                "runs": runs,
                "summaries": grouped,
                "comparison": comparison_table(grouped),
                "warning": (
                    "These figures are only as valid as the dataset used. "
                    "Synthetic smoke results are not scientific evidence."
                ),
            }
        else:
            rows = store.predictions_for_run(run_id)
            payload = summarize_run(rows, include_synthetic=include_synthetic)
        out = settings.resolve(settings.paths.results_dir) / "summaries"
        out.mkdir(parents=True, exist_ok=True)
        path = out / "latest.json"
        path.write_text(json.dumps(payload, indent=2, default=str))
        typer.echo(json.dumps(payload, indent=2, default=str))
    finally:
        store.close()


@benchmark_app.command("export")
def benchmark_export(
    latest: bool = typer.Option(False, "--latest"),
    run_id: Optional[str] = typer.Option(None),
) -> None:
    paths = export_run(None if latest else run_id)
    typer.echo(json.dumps({k: str(v) for k, v in paths.items()}, indent=2))


if __name__ == "__main__":
    app()
