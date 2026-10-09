from __future__ import annotations

import math
from collections import Counter
from typing import Any, Iterable, Sequence

import numpy as np


def _safe_div(num: float, den: float) -> float | None:
    if den == 0:
        return None
    return num / den


def confusion(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, int]:
    tp = fp = tn = fn = 0
    for t, p in zip(y_true, y_pred):
        if t == 1 and p == 1:
            tp += 1
        elif t == 0 and p == 1:
            fp += 1
        elif t == 0 and p == 0:
            tn += 1
        elif t == 1 and p == 0:
            fn += 1
    return {"tp": tp, "fp": fp, "tn": tn, "fn": fn}


def detection_metrics(y_true: Sequence[int], y_pred: Sequence[int]) -> dict[str, Any]:
    cm = confusion(y_true, y_pred)
    tp, fp, tn, fn = cm["tp"], cm["fp"], cm["tn"], cm["fn"]
    precision = _safe_div(tp, tp + fp)
    recall = _safe_div(tp, tp + fn)
    specificity = _safe_div(tn, tn + fp)
    fpr = _safe_div(fp, fp + tn)
    acc = _safe_div(tp + tn, tp + tn + fp + fn)
    f1 = None
    if precision is not None and recall is not None and (precision + recall) > 0:
        f1 = 2 * precision * recall / (precision + recall)
    elif precision is not None and recall is not None:
        f1 = 0.0
    tpr = recall
    tnr = specificity
    balanced = None
    if tpr is not None and tnr is not None:
        balanced = 0.5 * (tpr + tnr)
    labels = Counter(int(v) for v in y_true)
    return {
        "n": len(y_true),
        "class_distribution": {"vulnerable": labels.get(1, 0), "benign": labels.get(0, 0)},
        "confusion_matrix": cm,
        "precision": precision,
        "recall": recall,
        "f1": f1,
        "accuracy": acc,
        "balanced_accuracy": balanced,
        "specificity": specificity,
        "false_positive_rate": fpr,
    }


def brier_score(y_true: Sequence[int], p_vuln: Sequence[float]) -> float | None:
    if not y_true:
        return None
    err = [(float(p) - float(t)) ** 2 for t, p in zip(y_true, p_vuln)]
    return float(sum(err) / len(err))


def expected_calibration_error(
    y_true: Sequence[int],
    p_vuln: Sequence[float],
    *,
    n_bins: int = 10,
) -> dict[str, Any]:
    """Equal-width ECE over p_vulnerable in [0, 1] with `n_bins` bins.

    ECE = sum_i (n_i / N) * |acc_i - conf_i| where conf_i is mean p in the bin
    and acc_i is the fraction of true-vulnerable labels. These probabilities
    are treated as uncalibrated model outputs.
    """
    if not y_true:
        return {"ece": None, "n_bins": n_bins, "binning": "equal_width_[0,1]", "bins": []}
    y = np.asarray(y_true, dtype=float)
    p = np.clip(np.asarray(p_vuln, dtype=float), 0.0, 1.0)
    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins: list[dict[str, Any]] = []
    ece = 0.0
    n = len(y)
    for i in range(n_bins):
        lo, hi = edges[i], edges[i + 1]
        if i == n_bins - 1:
            mask = (p >= lo) & (p <= hi)
        else:
            mask = (p >= lo) & (p < hi)
        count = int(mask.sum())
        if count == 0:
            bins.append(
                {
                    "bin": i,
                    "lo": float(lo),
                    "hi": float(hi),
                    "count": 0,
                    "accuracy": None,
                    "confidence": None,
                    "gap": None,
                }
            )
            continue
        acc = float(y[mask].mean())
        conf = float(p[mask].mean())
        gap = abs(acc - conf)
        ece += (count / n) * gap
        bins.append(
            {
                "bin": i,
                "lo": float(lo),
                "hi": float(hi),
                "count": count,
                "accuracy": acc,
                "confidence": conf,
                "gap": gap,
            }
        )
    return {
        "ece": float(ece),
        "n_bins": n_bins,
        "binning": "equal_width_[0,1]",
        "bins": bins,
        "note": "p_vulnerable is evaluated as an uncalibrated score; do not call it calibrated confidence.",
    }


def ranking_metrics(y_true: Sequence[int], p_vuln: Sequence[float]) -> dict[str, Any]:
    labels = set(int(v) for v in y_true)
    out: dict[str, Any] = {"auroc": None, "auprc": None}
    if len(y_true) < 2 or len(labels) < 2:
        out["skipped_reason"] = "AUROC/AUPRC require both classes and at least 2 samples"
        return out
    try:
        from sklearn.metrics import average_precision_score, roc_auc_score
    except ImportError:
        out["skipped_reason"] = "scikit-learn not installed"
        return out
    y = np.asarray(y_true, dtype=int)
    p = np.asarray(p_vuln, dtype=float)
    try:
        out["auroc"] = float(roc_auc_score(y, p))
    except ValueError as exc:
        out["auroc_error"] = str(exc)
    try:
        out["auprc"] = float(average_precision_score(y, p))
    except ValueError as exc:
        out["auprc_error"] = str(exc)
    return out


def latency_stats(values: Sequence[float]) -> dict[str, float | None]:
    if not values:
        return {"n": 0, "mean": None, "median": None, "p50": None, "p90": None, "p95": None}
    arr = np.asarray(values, dtype=float)
    return {
        "n": int(arr.size),
        "mean": float(arr.mean()),
        "median": float(np.median(arr)),
        "p50": float(np.percentile(arr, 50)),
        "p90": float(np.percentile(arr, 90)),
        "p95": float(np.percentile(arr, 95)),
    }


def summarize_run(rows: list[dict[str, Any]], *, include_synthetic: bool = False) -> dict[str, Any]:
    considered = [
        r
        for r in rows
        if include_synthetic or not int(r.get("is_synthetic") or 0)
    ]
    if not considered and rows and all(int(r.get("is_synthetic") or 0) for r in rows):
        considered = list(rows)
        synthetic_only = True
    else:
        synthetic_only = bool(rows) and all(int(r.get("is_synthetic") or 0) for r in rows)

    n_total = len(considered)
    successes = [r for r in considered if r.get("status") == "success" and r.get("p_vulnerable") is not None]
    failures = [r for r in considered if r.get("status") != "success"]
    scan_fail = 0
    retr_fail = 0
    for row in considered:
        scan = _maybe_json(row.get("scan_json"))
        retr = _maybe_json(row.get("retrieved_json"))
        if isinstance(scan, dict) and scan.get("status") == "error":
            scan_fail += 1
        if isinstance(retr, dict) and retr.get("status") == "error":
            retr_fail += 1

    y_true = [int(r["ground_truth_label"]) for r in successes if r.get("ground_truth_label") is not None]
    y_pred = [
        1 if r.get("predicted_label") == "vulnerable" else 0
        for r in successes
        if r.get("ground_truth_label") is not None
    ]
    p_vals = [
        float(r["p_vulnerable"])
        for r in successes
        if r.get("ground_truth_label") is not None
    ]
    detection = detection_metrics(y_true, y_pred) if y_true else {
        "n": 0,
        "note": "no successful labelled predictions",
    }
    calibration = {
        "brier": brier_score(y_true, p_vals) if y_true else None,
        **expected_calibration_error(y_true, p_vals),
        **ranking_metrics(y_true, p_vals) if y_true else {"auroc": None, "auprc": None},
        "interpretation": (
            "Scores are uncalibrated model p_vulnerable values. "
            "Post-hoc calibration must be fit on a validation split, never the test set."
        ),
    }
    latencies = [
        float(r["latency_seconds"])
        for r in successes
        if r.get("latency_seconds") is not None
    ]
    paper_ok = (not synthetic_only) and n_total > 0 and not all(
        int(r.get("is_synthetic") or 0) for r in considered
    )
    return {
        "n_rows": n_total,
        "n_success": len(successes),
        "n_failed": len(failures),
        "failed_sample_ids": [r.get("sample_id") for r in failures],
        "successful_inference_rate": _safe_div(len(successes), n_total) if n_total else None,
        "scanner_failure_rate": _safe_div(scan_fail, n_total) if n_total else None,
        "retrieval_failure_rate": _safe_div(retr_fail, n_total) if n_total else None,
        "n_scanner_failures": scan_fail,
        "n_retrieval_failures": retr_fail,
        "detection": detection,
        "calibration": calibration,
        "latency": latency_stats(latencies),
        "synthetic_only": synthetic_only,
        "include_synthetic": include_synthetic,
        "suitable_for_paper": paper_ok and not synthetic_only,
        "caveat": (
            "Synthetic smoke samples must not be reported as scientific benchmark results."
            if synthetic_only
            else None
        ),
    }


def _maybe_json(value: Any) -> Any:
    if value is None:
        return None
    if isinstance(value, (dict, list)):
        return value
    if isinstance(value, str) and value.strip().startswith(("{", "[")):
        import json

        try:
            return json.loads(value)
        except json.JSONDecodeError:
            return None
    return None


def comparison_table(summaries: dict[str, dict[str, Any]]) -> list[dict[str, Any]]:
    rows = []
    for config_name, summary in summaries.items():
        det = summary.get("detection") or {}
        cal = summary.get("calibration") or {}
        rows.append(
            {
                "config": config_name,
                "n_success": summary.get("n_success"),
                "n_failed": summary.get("n_failed"),
                "precision": det.get("precision"),
                "recall": det.get("recall"),
                "f1": det.get("f1"),
                "accuracy": det.get("accuracy"),
                "balanced_accuracy": det.get("balanced_accuracy"),
                "specificity": det.get("specificity"),
                "false_positive_rate": det.get("false_positive_rate"),
                "brier": cal.get("brier"),
                "ece": cal.get("ece"),
                "auroc": cal.get("auroc"),
                "auprc": cal.get("auprc"),
                "mean_latency": (summary.get("latency") or {}).get("mean"),
                "successful_inference_rate": summary.get("successful_inference_rate"),
                "suitable_for_paper": summary.get("suitable_for_paper"),
            }
        )
    return rows
