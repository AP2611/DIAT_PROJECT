from __future__ import annotations

from vulntriage.ollama_client import parse_prediction_json
from vulntriage.schemas import LLMPrediction


def test_prediction_validates_and_derives_label():
    pred = LLMPrediction(
        predicted_label="benign",
        p_vulnerable=0.8,
        reasoning="conflict",
        evidence=["scanner says vuln"],
        limitations="disagreeing sources",
    )
    assert pred.derived_label(0.5).value == "vulnerable"
    assert pred.decision_confidence() == 0.8


def test_parse_fenced_json():
    text = """Here you go
```json
{"predicted_label": "benign", "p_vulnerable": 0.1, "reasoning": "ok", "evidence": [], "limitations": "none"}
```
"""
    parsed, err = parse_prediction_json(text)
    assert err is None
    assert parsed is not None
    assert parsed.predicted_label.value == "benign"
    assert parsed.p_vulnerable == 0.1


def test_malformed_json_is_recorded():
    parsed, err = parse_prediction_json("not json")
    assert parsed is None
    assert err
