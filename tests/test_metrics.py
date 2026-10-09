from __future__ import annotations

from vulntriage.metrics import (
    brier_score,
    detection_metrics,
    expected_calibration_error,
    summarize_run,
)


def test_detection_zero_division():
    # all predicted negative, no positives predicted
    m = detection_metrics([1, 0], [0, 0])
    assert m["precision"] is None
    assert m["recall"] == 0.0
    assert m["confusion_matrix"]["fn"] == 1
    assert m["n"] == 2


def test_perfect_detection():
    m = detection_metrics([1, 0, 1, 0], [1, 0, 1, 0])
    assert m["precision"] == 1
    assert m["recall"] == 1
    assert m["f1"] == 1
    assert m["accuracy"] == 1
    assert m["balanced_accuracy"] == 1
    assert m["specificity"] == 1
    assert m["false_positive_rate"] == 0


def test_brier_and_ece():
    y = [1, 0, 1, 0]
    p = [1.0, 0.0, 1.0, 0.0]
    assert brier_score(y, p) == 0.0
    ece = expected_calibration_error(y, p, n_bins=10)
    assert ece["ece"] == 0.0
    assert ece["binning"] == "equal_width_[0,1]"
    assert ece["n_bins"] == 10


def test_summarize_keeps_failures():
    rows = [
        {
            "status": "success",
            "is_synthetic": 0,
            "ground_truth_label": 1,
            "predicted_label": "vulnerable",
            "p_vulnerable": 0.9,
            "latency_seconds": 1.0,
            "sample_id": "a",
        },
        {
            "status": "error",
            "is_synthetic": 0,
            "ground_truth_label": 0,
            "predicted_label": None,
            "p_vulnerable": None,
            "sample_id": "b",
            "error": "timeout",
        },
    ]
    summary = summarize_run(rows)
    assert summary["n_failed"] == 1
    assert summary["failed_sample_ids"] == ["b"]
    assert summary["n_success"] == 1
    assert summary["detection"]["n"] == 1
