from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

import httpx

from vulntriage.schemas import LLMPrediction, PREDICTION_JSON_SCHEMA

JSON_FENCE = re.compile(r"```(?:json)?\s*(\{.*?\})\s*```", re.DOTALL)
JSON_OBJECT = re.compile(r"\{.*\}", re.DOTALL)


class OllamaError(RuntimeError):
    pass


@dataclass
class OllamaResponse:
    raw_text: str
    parsed: LLMPrediction | None
    parse_error: str | None
    model: str
    used_schema: bool
    latency_seconds: float
    prompt_eval_count: int | None = None
    eval_count: int | None = None
    total_duration_ns: int | None = None
    extra: dict[str, Any] = field(default_factory=dict)


class OllamaClient:
    def __init__(
        self,
        url: str = "http://localhost:11434",
        model: str = "mistral",
        temperature: float = 0.0,
        num_ctx: int = 8192,
        num_predict: int = 1024,
        timeout_seconds: float = 180.0,
        use_json_schema: bool = True,
    ) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise ValueError(f"Invalid Ollama URL: {url}")
        self.url = url.rstrip("/")
        self.model = model
        self.temperature = temperature
        self.num_ctx = num_ctx
        self.num_predict = num_predict
        self.timeout_seconds = timeout_seconds
        self.use_json_schema = use_json_schema

    def health(self) -> dict[str, Any]:
        try:
            version = httpx.get(f"{self.url}/api/version", timeout=5.0).json()
            tags = httpx.get(f"{self.url}/api/tags", timeout=10.0).json()
        except httpx.HTTPError as exc:
            raise OllamaError(
                f"Ollama is not reachable at {self.url}: {exc}. "
                "Start it with: /opt/homebrew/bin/ollama serve"
            ) from exc
        models = tags.get("models") or []
        names = [m.get("name") or m.get("model") for m in models]
        configured_available = any(
            n == self.model or (n and n.split(":")[0] == self.model.split(":")[0])
            for n in names
            if n
        )
        details: dict[str, Any] = {}
        if configured_available:
            try:
                show = httpx.post(
                    f"{self.url}/api/show",
                    json={"name": self.model},
                    timeout=10.0,
                )
                if show.status_code == 200:
                    details = show.json()
            except httpx.HTTPError:
                details = {}
        return {
            "reachable": True,
            "url": self.url,
            "version": version,
            "models": models,
            "model_names": names,
            "configured_model": self.model,
            "configured_model_available": configured_available,
            "model_details": {
                "modelfile": (details.get("modelfile") or "")[:200],
                "details": details.get("details"),
                "digest": details.get("digest") or details.get("modified_at"),
                "modified_at": details.get("modified_at"),
            },
        }

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        format_schema: dict[str, Any] | None = None,
    ) -> OllamaResponse:
        schema = format_schema if format_schema is not None else PREDICTION_JSON_SCHEMA
        used_schema = bool(self.use_json_schema)
        payload: dict[str, Any] = {
            "model": self.model,
            "messages": messages,
            "stream": False,
            "format": schema if used_schema else "json",
            "options": {
                "temperature": self.temperature,
                "num_ctx": self.num_ctx,
                "num_predict": self.num_predict,
            },
        }
        started = time.perf_counter()
        try:
            response = httpx.post(
                f"{self.url}/api/chat",
                json=payload,
                timeout=self.timeout_seconds,
            )
        except httpx.TimeoutException as exc:
            raise OllamaError(f"Ollama timed out after {self.timeout_seconds}s") from exc
        except httpx.HTTPError as exc:
            raise OllamaError(f"Ollama request failed: {exc}") from exc

        if response.status_code >= 400:
            # Schema-constrained format may be unsupported; retry with json mode.
            if used_schema and response.status_code in {400, 422, 500}:
                payload["format"] = "json"
                used_schema = False
                try:
                    response = httpx.post(
                        f"{self.url}/api/chat",
                        json=payload,
                        timeout=self.timeout_seconds,
                    )
                except httpx.HTTPError as exc:
                    raise OllamaError(f"Ollama request failed: {exc}") from exc
            if response.status_code >= 400:
                raise OllamaError(
                    f"Ollama HTTP {response.status_code}: {response.text[:500]}"
                )

        latency = time.perf_counter() - started
        body = response.json()
        raw_text = ((body.get("message") or {}).get("content")) or body.get("response") or ""
        parsed, parse_error = parse_prediction_json(raw_text)
        return OllamaResponse(
            raw_text=raw_text,
            parsed=parsed,
            parse_error=parse_error,
            model=body.get("model") or self.model,
            used_schema=used_schema,
            latency_seconds=latency,
            prompt_eval_count=body.get("prompt_eval_count"),
            eval_count=body.get("eval_count"),
            total_duration_ns=body.get("total_duration"),
            extra={"done_reason": body.get("done_reason"), "created_at": body.get("created_at")},
        )


def parse_prediction_json(text: str) -> tuple[LLMPrediction | None, str | None]:
    if not text or not str(text).strip():
        return None, "empty model response"
    candidates = [text.strip()]
    fenced = JSON_FENCE.search(text)
    if fenced:
        candidates.insert(0, fenced.group(1))
    obj = JSON_OBJECT.search(text)
    if obj:
        candidates.append(obj.group(0))
    errors: list[str] = []
    for candidate in candidates:
        try:
            data = json.loads(candidate)
        except json.JSONDecodeError as exc:
            errors.append(str(exc))
            continue
        try:
            return LLMPrediction.model_validate(data), None
        except Exception as exc:  # pydantic ValidationError
            errors.append(str(exc))
    return None, "; ".join(errors[:3])
