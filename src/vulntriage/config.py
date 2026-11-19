from __future__ import annotations

import os
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, Field

ROOT = Path(__file__).resolve().parents[2]


def _load_dotenv(path: Path) -> None:
    """Load KEY=VALUE pairs from .env without overriding real environment variables."""
    if not path.exists():
        return
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        key, value = key.strip(), value.strip()
        if key and value:
            os.environ.setdefault(key, value)


class OllamaSettings(BaseModel):
    url: str = "http://localhost:11434"
    model: str = "mistral"
    temperature: float = 0.0
    num_ctx: int = 8192
    num_predict: int = 1024
    timeout_seconds: float = 180.0
    use_json_schema: bool = True


class GeminiSettings(BaseModel):
    model: str = "gemini-3.1-flash-lite"
    base_url: str = "https://generativelanguage.googleapis.com/v1beta"
    api_key: str = ""
    temperature: float = 0.0
    max_output_tokens: int = 1024
    timeout_seconds: float = 120.0


class EmbeddingsSettings(BaseModel):
    model_name: str = "sentence-transformers/all-MiniLM-L6-v2"
    device: str = "cpu"
    batch_size: int = 32
    collection_name: str = "security_knowledge"
    top_k: int = 5


class SemgrepSettings(BaseModel):
    config: str = "configs/semgrep.yml"
    timeout_seconds: float = 60.0


class PathsSettings(BaseModel):
    raw_data_dir: str = "data/raw"
    processed_dir: str = "data/processed"
    benchmark_dir: str = "data/benchmark"
    qdrant_path: str = "data/qdrant"
    results_dir: str = "results"
    sqlite_path: str = "results/experiments.sqlite"
    research_dir: str = "research"


class Settings(BaseModel):
    project_name: str = "vulntriage"
    provider: str = "ollama"
    decision_threshold: float = 0.5
    prompt_version: str = "v1"
    paths: PathsSettings = Field(default_factory=PathsSettings)
    ollama: OllamaSettings = Field(default_factory=OllamaSettings)
    gemini: GeminiSettings = Field(default_factory=GeminiSettings)
    embeddings: EmbeddingsSettings = Field(default_factory=EmbeddingsSettings)
    semgrep: SemgrepSettings = Field(default_factory=SemgrepSettings)
    max_code_chars: int = 8000
    cache_predictions: bool = True
    default_seed: int = 42

    def resolve(self, path: str | Path) -> Path:
        p = Path(path)
        if not p.is_absolute():
            p = ROOT / p
        return p


def _deep_update(base: dict[str, Any], extra: dict[str, Any]) -> dict[str, Any]:
    out = dict(base)
    for key, value in extra.items():
        if isinstance(value, dict) and isinstance(out.get(key), dict):
            out[key] = _deep_update(out[key], value)
        else:
            out[key] = value
    return out


def load_settings(config_path: str | Path | None = None) -> Settings:
    _load_dotenv(ROOT / ".env")
    path = Path(config_path) if config_path else ROOT / "configs" / "default.yaml"
    data: dict[str, Any] = {}
    if path.exists():
        loaded = yaml.safe_load(path.read_text()) or {}
        data = loaded
        generation = data.pop("generation", {}) or {}
        benchmark = data.pop("benchmark", {}) or {}
        if "max_code_chars" in generation:
            data["max_code_chars"] = generation["max_code_chars"]
        if "cache_predictions" in benchmark:
            data["cache_predictions"] = benchmark["cache_predictions"]
        if "default_seed" in benchmark:
            data["default_seed"] = benchmark["default_seed"]

    env_overlay: dict[str, Any] = {
        "ollama": {}, "gemini": {}, "paths": {}, "embeddings": {}, "semgrep": {}
    }
    if os.getenv("VULNTRIAGE_PROVIDER"):
        data["provider"] = os.environ["VULNTRIAGE_PROVIDER"]
    if os.getenv("VULNTRIAGE_GEMINI_MODEL"):
        env_overlay["gemini"]["model"] = os.environ["VULNTRIAGE_GEMINI_MODEL"]
    if os.getenv("VULNTRIAGE_GEMINI_BASE_URL"):
        env_overlay["gemini"]["base_url"] = os.environ["VULNTRIAGE_GEMINI_BASE_URL"]
    if os.getenv("GEMINI_API_KEY"):
        env_overlay["gemini"]["api_key"] = os.environ["GEMINI_API_KEY"]
    if os.getenv("VULNTRIAGE_OLLAMA_URL"):
        env_overlay["ollama"]["url"] = os.environ["VULNTRIAGE_OLLAMA_URL"]
    if os.getenv("VULNTRIAGE_OLLAMA_MODEL"):
        env_overlay["ollama"]["model"] = os.environ["VULNTRIAGE_OLLAMA_MODEL"]
    if os.getenv("VULNTRIAGE_RAW_DATA_DIR"):
        env_overlay["paths"]["raw_data_dir"] = os.environ["VULNTRIAGE_RAW_DATA_DIR"]
    if os.getenv("VULNTRIAGE_EMBEDDING_MODEL"):
        env_overlay["embeddings"]["model_name"] = os.environ["VULNTRIAGE_EMBEDDING_MODEL"]
    if os.getenv("VULNTRIAGE_SEMGREP_CONFIG"):
        env_overlay["semgrep"]["config"] = os.environ["VULNTRIAGE_SEMGREP_CONFIG"]
    if os.getenv("VULNTRIAGE_TOP_K"):
        env_overlay["embeddings"]["top_k"] = int(os.environ["VULNTRIAGE_TOP_K"])
    if os.getenv("VULNTRIAGE_DECISION_THRESHOLD"):
        data["decision_threshold"] = float(os.environ["VULNTRIAGE_DECISION_THRESHOLD"])
    if os.getenv("VULNTRIAGE_NUM_CTX"):
        env_overlay["ollama"]["num_ctx"] = int(os.environ["VULNTRIAGE_NUM_CTX"])
    if os.getenv("VULNTRIAGE_NUM_PREDICT"):
        env_overlay["ollama"]["num_predict"] = int(os.environ["VULNTRIAGE_NUM_PREDICT"])

    env_overlay = {k: v for k, v in env_overlay.items() if v}
    data = _deep_update(data, env_overlay)
    return Settings.model_validate(data)
