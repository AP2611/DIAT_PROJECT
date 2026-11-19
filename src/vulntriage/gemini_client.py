from __future__ import annotations

import time
from typing import Any


import httpx

from vulntriage.config import Settings
from vulntriage.ollama_client import OllamaError, OllamaResponse, parse_prediction_json
from vulntriage.schemas import PREDICTION_JSON_SCHEMA


class GeminiError(OllamaError):
    """Raised for Gemini API failures. Subclasses OllamaError so run_sample catches it."""


class GeminiClient:
    """Hosted Gemini client with the same chat() interface as OllamaClient."""

    def __init__(
        self,
        *,
        api_key: str,
        model: str = "gemini-3.1-flash-lite",
        base_url: str = "https://generativelanguage.googleapis.com/v1beta",
        temperature: float = 0.0,
        max_output_tokens: int = 1024,
        timeout_seconds: float = 120.0,
    ) -> None:
        if not api_key or api_key == "your_key_here":
            raise GeminiError("GEMINI_API_KEY is missing or still a placeholder")
        self.api_key = api_key
        self.model = model
        self.base_url = base_url.rstrip("/")
        # Attributes used by ExperimentContext / run metadata.
        self.temperature = temperature
        self.num_ctx = None
        self.num_predict = max_output_tokens
        self.use_json_schema = True
        self.timeout_seconds = timeout_seconds

    @classmethod
    def from_settings(cls, settings: Settings) -> "GeminiClient":
        return cls(
            api_key=settings.gemini.api_key,
            model=settings.gemini.model,
            base_url=settings.gemini.base_url,
            temperature=settings.gemini.temperature,
            max_output_tokens=settings.gemini.max_output_tokens,
            timeout_seconds=settings.gemini.timeout_seconds,
        )

    def health(self) -> dict[str, Any]:
        return {
            "reachable": True,
            "version": "v1beta",
            "configured_model": self.model,
            "configured_model_available": True,
            "model_names": [self.model],
            "model_details": {"digest": self.model},
        }

    @staticmethod
    def _build_payload(
        messages: list[dict[str, str]], schema: dict[str, Any], temperature: float, max_tokens: int
    ) -> dict[str, Any]:
        system_texts = [m["content"] for m in messages if m["role"] == "system"]
        contents = [
            {
                "role": "user" if m["role"] == "user" else "model",
                "parts": [{"text": m["content"]}],
            }
            for m in messages
            if m["role"] != "system"
        ]
        payload: dict[str, Any] = {
            "contents": contents,
            "generationConfig": {
                "temperature": temperature,
                "maxOutputTokens": max_tokens,
                "responseMimeType": "application/json",
                "responseJsonSchema": schema,
            },
        }
        if system_texts:
            payload["systemInstruction"] = {"parts": [{"text": "\n\n".join(system_texts)}]}
        return payload

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        format_schema: dict[str, Any] | None = None,
    ) -> OllamaResponse:
        schema = format_schema if format_schema is not None else PREDICTION_JSON_SCHEMA
        payload = self._build_payload(messages, schema, self.temperature, self.num_predict)
        url = f"{self.base_url}/models/{self.model}:generateContent"
        started = time.perf_counter()
        max_retries = 3
        for attempt in range(max_retries):
            try:
                response = httpx.post(
                    url,
                    params={"key": self.api_key},
                    json=payload,
                    timeout=self.timeout_seconds,
                )
            except httpx.TimeoutException as exc:
                raise GeminiError(f"Gemini timed out after {self.timeout_seconds}s") from exc
            except httpx.HTTPError as exc:
                raise GeminiError(f"Gemini request failed: {exc}") from exc

            if response.status_code in {429, 503} and attempt < max_retries - 1:
                time.sleep(2 * (attempt + 1))
                continue
            if response.status_code >= 400:
                raise GeminiError(
                    f"Gemini HTTP {response.status_code}: {response.text[:500]}"
                )
            break

        latency = time.perf_counter() - started
        body = response.json()
        candidates = body.get("candidates") or []
        parts = (candidates[0].get("content") or {}).get("parts") if candidates else None
        raw_text = "".join(str(p.get("text") or "") for p in (parts or []))
        parsed, parse_error = parse_prediction_json(raw_text)
        usage = body.get("usageMetadata") or {}
        return OllamaResponse(
            raw_text=raw_text,
            parsed=parsed,
            parse_error=parse_error,
            model=self.model,
            used_schema=True,
            latency_seconds=latency,
            prompt_eval_count=usage.get("promptTokenCount"),
            eval_count=usage.get("candidatesTokenCount"),
            extra={"service_tier": usage.get("serviceTier")},
        )
