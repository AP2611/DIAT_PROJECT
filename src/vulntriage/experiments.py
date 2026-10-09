from __future__ import annotations

import json
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable

from vulntriage.ollama_client import OllamaClient, OllamaError
from vulntriage.prompts import PROMPT_VERSION, build_messages
from vulntriage.schemas import (
    CanonicalSample,
    DECISION_THRESHOLD,
    RetrievalResult,
    ScanResult,
)
from vulntriage.static_analysis import scan_code
from vulntriage.storage import make_cache_key

USES_SAST = {"llm_sast", "llm_sast_rag"}
USES_RAG = {"llm_rag", "llm_sast_rag"}


@dataclass
class ExperimentContext:
    config_name: str
    client: OllamaClient
    decision_threshold: float = DECISION_THRESHOLD
    max_code_chars: int = 8000
    semgrep_config: str | None = None
    semgrep_timeout: float = 60.0
    retrieve: Callable[[CanonicalSample], RetrievalResult] | None = None
    index_version: str | None = None
    embedding_model: str | None = None


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def run_sample(sample: CanonicalSample, ctx: ExperimentContext) -> dict[str, Any]:
    started = _now()
    scan: ScanResult | None = None
    retrieval: RetrievalResult | None = None
    if ctx.config_name in USES_SAST:
        if not ctx.semgrep_config:
            scan = ScanResult(status="error", error="semgrep config not provided")
        else:
            scan = scan_code(
                sample.code,
                config=ctx.semgrep_config,
                language_hint=sample.language,
                timeout_seconds=ctx.semgrep_timeout,
            )
    if ctx.config_name in USES_RAG:
        if ctx.retrieve is None:
            retrieval = RetrievalResult(
                status="error",
                error="retriever not configured",
                embedding_model=ctx.embedding_model,
                index_version=ctx.index_version,
            )
        else:
            retrieval = ctx.retrieve(sample)

    messages = build_messages(
        code=sample.code,
        config_name=ctx.config_name,
        scan=scan,
        retrieval=retrieval,
        max_code_chars=ctx.max_code_chars,
        language=sample.language,
    )
    # Guardrail: never leak labels into the prompt payload we log.
    prompt_blob = json.dumps(messages)
    for forbidden in (str(sample.label),):
        # Labels are 0/1; do not scan the whole prompt for "0"/"1". Check dedicated fields only.
        pass
    if '"label"' in prompt_blob.lower() and "ground" in prompt_blob.lower():
        raise RuntimeError("Refusing to send a prompt that appears to contain ground-truth labels")

    generation_settings = {
        "temperature": ctx.client.temperature,
        "num_ctx": ctx.client.num_ctx,
        "num_predict": ctx.client.num_predict,
        "use_json_schema": ctx.client.use_json_schema,
    }
    cache_key = make_cache_key(
        sample_id=sample.sample_id,
        code=sample.code,
        config_name=ctx.config_name,
        model_name=ctx.client.model,
        prompt_version=PROMPT_VERSION,
        generation_settings=generation_settings,
        embedding_model=ctx.embedding_model if ctx.config_name in USES_RAG else None,
        index_version=ctx.index_version if ctx.config_name in USES_RAG else None,
        semgrep_config=ctx.semgrep_config if ctx.config_name in USES_SAST else None,
        decision_threshold=ctx.decision_threshold,
    )
    record: dict[str, Any] = {
        "sample_id": sample.sample_id,
        "config_name": ctx.config_name,
        "cache_key": cache_key,
        "started_at": started,
        "ground_truth_label": sample.label,
        "is_synthetic": int(sample.is_synthetic),
        "retrieved_json": retrieval.model_dump_json() if retrieval else None,
        "scan_json": scan.model_dump_json() if scan else None,
        "prompt_json": json.dumps(
            [{"role": m["role"], "n_chars": len(m["content"])} for m in messages]
        ),
        "status": "error",
    }
    try:
        response = ctx.client.chat(messages)
    except OllamaError as exc:
        record.update(
            {
                "ended_at": _now(),
                "error": str(exc),
                "raw_response": None,
                "status": "error",
            }
        )
        return record

    ended = _now()
    record["ended_at"] = ended
    record["latency_seconds"] = response.latency_seconds
    record["raw_response"] = response.raw_text
    record["prompt_eval_count"] = response.prompt_eval_count
    record["eval_count"] = response.eval_count
    if response.parsed is None:
        record["error"] = f"invalid prediction JSON: {response.parse_error}"
        record["status"] = "error"
        return record

    derived = response.parsed.derived_label(ctx.decision_threshold)
    record.update(
        {
            "status": "success",
            "predicted_label": derived.value,
            "model_predicted_label": response.parsed.predicted_label.value,
            "p_vulnerable": response.parsed.p_vulnerable,
            "decision_confidence": response.parsed.decision_confidence(),
            "predicted_cwe": response.parsed.cwe_id,
            "reasoning": response.parsed.reasoning,
            "evidence": json.dumps(response.parsed.evidence),
            "limitations": response.parsed.limitations,
            "error": None,
        }
    )
    return record
