from __future__ import annotations

from vulntriage.ollama_client import OllamaResponse
from vulntriage.schemas import LLMPrediction, PredictedLabel


class FakeOllama:
    def __init__(self, p: float = 0.9) -> None:
        self.model = "mistral"
        self.temperature = 0.0
        self.num_ctx = 2048
        self.num_predict = 128
        self.use_json_schema = True
        self.calls = 0
        self.p = p
        self.messages_seen: list = []

    def chat(self, messages, format_schema=None):
        self.calls += 1
        self.messages_seen.append(messages)
        pred = LLMPrediction(
            predicted_label=PredictedLabel.vulnerable if self.p >= 0.5 else PredictedLabel.benign,
            p_vulnerable=self.p,
            cwe_id="CWE-89",
            reasoning="unit-test stub",
            evidence=["code uses string-formatted SQL"] if self.p >= 0.5 else ["no sinks"],
            limitations="stub",
        )
        return OllamaResponse(
            raw_text=pred.model_dump_json(),
            parsed=pred,
            parse_error=None,
            model=self.model,
            used_schema=True,
            latency_seconds=0.01,
            prompt_eval_count=10,
            eval_count=20,
        )
