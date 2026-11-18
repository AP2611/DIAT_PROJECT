from __future__ import annotations

from vulntriage.experiments import detect_constant_predictions


def test_detect_constant_predictions_returns_none_when_varied():
    records = [
        {"status": "success", "p_vulnerable": 0.1},
        {"status": "success", "p_vulnerable": 0.9},
    ]
    assert detect_constant_predictions(records) is None


def test_detect_constant_predictions_returns_diagnostic_when_constant():
    records = [
        {"status": "success", "p_vulnerable": 0.1},
        {"status": "success", "p_vulnerable": 0.1},
        {"status": "success", "p_vulnerable": 0.1},
    ]
    diag = detect_constant_predictions(records)
    assert diag is not None
    assert diag["constant_score"] == 0.1
    assert diag["n_samples"] == 3
    assert "not discriminating" in diag["warning"]


def test_detect_constant_predictions_ignores_errors():
    records = [
        {"status": "success", "p_vulnerable": 0.1},
        {"status": "error", "p_vulnerable": None},
        {"status": "error", "p_vulnerable": None},
    ]
    diag = detect_constant_predictions(records)
    assert diag is not None
    assert diag["n_samples"] == 1


def test_detect_constant_predictions_empty_returns_none():
    assert detect_constant_predictions([]) is None
    assert detect_constant_predictions([{"status": "error"}]) is None
