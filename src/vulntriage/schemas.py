from __future__ import annotations

from enum import Enum
from typing import Any, Literal

from pydantic import BaseModel, Field, field_validator, model_validator

CONFIG_NAME = Literal["llm_only", "llm_sast", "llm_rag", "llm_sast_rag"]
DECISION_THRESHOLD = 0.5


class PredictedLabel(str, Enum):
    vulnerable = "vulnerable"
    benign = "benign"


class CanonicalSample(BaseModel):
    """Canonical labelled sample. Ground-truth is never sent to the model."""

    sample_id: str
    code: str
    label: int = Field(description="1 = vulnerable, 0 = benign")
    source_dataset: str
    cwe_id: str | None = None
    cve_id: str | None = None
    project_id: str | None = None
    commit_hash: str | None = None
    split: str | None = None
    language: str | None = None
    file_name: str | None = None
    func_hash: str | None = None
    is_synthetic: bool = False
    notes: str | None = None
    extra: dict[str, Any] = Field(default_factory=dict)

    @field_validator("label", mode="before")
    @classmethod
    def normalize_label(cls, value: Any) -> int:
        return normalize_binary_label(value)

    @field_validator("cwe_id", "cve_id", mode="before")
    @classmethod
    def empty_to_none(cls, value: Any) -> str | None:
        if value is None:
            return None
        if isinstance(value, list):
            if not value:
                return None
            value = value[0]
        text = str(value).strip()
        return text or None


class LLMPrediction(BaseModel):
    """Structured model output. Binary decision is derived from p_vulnerable."""

    predicted_label: PredictedLabel
    p_vulnerable: float = Field(ge=0.0, le=1.0)
    cwe_id: str | None = None
    reasoning: str
    evidence: list[str] = Field(default_factory=list)
    limitations: str = ""

    @field_validator("cwe_id", mode="before")
    @classmethod
    def empty_cwe(cls, value: Any) -> str | None:
        if value is None:
            return None
        text = str(value).strip()
        if not text or text.lower() in {"none", "null", "n/a", "unknown"}:
            return None
        return text

    @field_validator("evidence", mode="before")
    @classmethod
    def evidence_as_list(cls, value: Any) -> list[str]:
        if value is None:
            return []
        if isinstance(value, str):
            return [value] if value.strip() else []
        if isinstance(value, list):
            out: list[str] = []
            for item in value:
                if isinstance(item, dict):
                    claim = item.get("claim") or item.get("text") or str(item)
                    out.append(str(claim))
                else:
                    out.append(str(item))
            return out
        return [str(value)]

    @model_validator(mode="after")
    def clamp_probability(self) -> "LLMPrediction":
        self.p_vulnerable = float(min(1.0, max(0.0, self.p_vulnerable)))
        return self

    def derived_label(self, threshold: float = DECISION_THRESHOLD) -> PredictedLabel:
        if self.p_vulnerable >= threshold:
            return PredictedLabel.vulnerable
        return PredictedLabel.benign

    def decision_confidence(self) -> float:
        """P(chosen class) under a two-class interpretation of p_vulnerable.

        This is not a calibrated confidence that the prediction is correct.
        """
        return max(self.p_vulnerable, 1.0 - self.p_vulnerable)


class SemgrepFinding(BaseModel):
    rule_id: str
    message: str
    severity: str | None = None
    path: str | None = None
    start_line: int | None = None
    end_line: int | None = None
    start_col: int | None = None
    cwe: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)


class ScanResult(BaseModel):
    status: Literal["ok", "error", "skipped"]
    findings: list[SemgrepFinding] = Field(default_factory=list)
    version: str | None = None
    config: str | None = None
    error: str | None = None
    raw: dict[str, Any] = Field(default_factory=dict)


class RetrievedDocument(BaseModel):
    document_id: str
    score: float
    source: str
    source_version: str | None = None
    identifier: str | None = None
    title: str | None = None
    description: str | None = None
    relationships: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)


class RetrievalResult(BaseModel):
    status: Literal["ok", "error", "skipped"]
    documents: list[RetrievedDocument] = Field(default_factory=list)
    query: str | None = None
    excluded_identifiers: list[str] = Field(default_factory=list)
    error: str | None = None
    index_version: str | None = None
    embedding_model: str | None = None


class KnowledgeDocument(BaseModel):
    document_id: str
    source: str
    source_version: str | None = None
    identifier: str | None = None
    title: str
    description: str
    relationships: list[str] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    extra: dict[str, Any] = Field(default_factory=dict)

    def embed_text(self) -> str:
        rel = "; ".join(self.relationships[:12])
        return (
            f"{self.identifier or ''} {self.title}\n{self.description}\n{rel}"
        ).strip()


PREDICTION_JSON_SCHEMA: dict[str, Any] = {
    "type": "object",
    "properties": {
        "predicted_label": {"type": "string", "enum": ["vulnerable", "benign"]},
        "p_vulnerable": {"type": "number", "minimum": 0, "maximum": 1},
        "cwe_id": {"type": ["string", "null"]},
        "reasoning": {"type": "string"},
        "evidence": {"type": "array", "items": {"type": "string"}},
        "limitations": {"type": "string"},
    },
    "required": [
        "predicted_label",
        "p_vulnerable",
        "reasoning",
        "evidence",
        "limitations",
    ],
}


def normalize_binary_label(value: Any) -> int:
    if isinstance(value, bool):
        return int(value)
    if isinstance(value, (int, float)) and value in (0, 1):
        return int(value)
    if isinstance(value, str):
        text = value.strip().lower()
        if text in {"1", "true", "vulnerable", "vuln", "yes", "positive"}:
            return 1
        if text in {"0", "false", "benign", "safe", "no", "negative"}:
            return 0
    raise ValueError(f"Cannot normalize binary label: {value!r}")
