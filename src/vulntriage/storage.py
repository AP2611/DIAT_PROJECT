from __future__ import annotations

import csv
import hashlib
import json
import sqlite3
from datetime import datetime, timezone
from pathlib import Path
from typing import Any, Iterable


SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    created_at TEXT NOT NULL,
    config_name TEXT NOT NULL,
    dataset_name TEXT,
    dataset_version TEXT,
    model_name TEXT,
    model_digest TEXT,
    prompt_version TEXT,
    embedding_model TEXT,
    index_version TEXT,
    semgrep_version TEXT,
    semgrep_config TEXT,
    generation_settings TEXT,
    decision_threshold REAL,
    git_commit TEXT,
    notes TEXT,
    status TEXT NOT NULL DEFAULT 'running'
);

CREATE TABLE IF NOT EXISTS predictions (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    sample_id TEXT NOT NULL,
    config_name TEXT NOT NULL,
    cache_key TEXT NOT NULL,
    created_at TEXT NOT NULL,
    started_at TEXT,
    ended_at TEXT,
    latency_seconds REAL,
    ground_truth_label INTEGER,
    is_synthetic INTEGER,
    predicted_label TEXT,
    model_predicted_label TEXT,
    p_vulnerable REAL,
    decision_confidence REAL,
    predicted_cwe TEXT,
    reasoning TEXT,
    evidence TEXT,
    limitations TEXT,
    retrieved_json TEXT,
    scan_json TEXT,
    prompt_json TEXT,
    raw_response TEXT,
    status TEXT NOT NULL,
    error TEXT,
    prompt_eval_count INTEGER,
    eval_count INTEGER,
    reused_from INTEGER,
    UNIQUE(run_id, sample_id, config_name)
);

CREATE TABLE IF NOT EXISTS metrics (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    config_name TEXT NOT NULL,
    created_at TEXT NOT NULL,
    payload TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_predictions_cache ON predictions(cache_key);
CREATE INDEX IF NOT EXISTS idx_predictions_run ON predictions(run_id);
"""


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def make_cache_key(
    *,
    sample_id: str,
    code: str,
    config_name: str,
    model_name: str,
    prompt_version: str,
    generation_settings: dict[str, Any],
    embedding_model: str | None,
    index_version: str | None,
    semgrep_config: str | None,
    decision_threshold: float,
) -> str:
    payload = {
        "sample_id": sample_id,
        "code_sha256": hashlib.sha256(code.encode()).hexdigest(),
        "config_name": config_name,
        "model_name": model_name,
        "prompt_version": prompt_version,
        "generation_settings": generation_settings,
        "embedding_model": embedding_model,
        "index_version": index_version,
        "semgrep_config": semgrep_config,
        "decision_threshold": decision_threshold,
    }
    blob = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256(blob.encode()).hexdigest()


class ExperimentStore:
    def __init__(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        self.path = path
        self._conn = sqlite3.connect(str(path))
        self._conn.row_factory = sqlite3.Row
        self._conn.executescript(SCHEMA)
        self._conn.commit()

    def close(self) -> None:
        self._conn.close()

    def create_run(self, run_id: str, metadata: dict[str, Any]) -> None:
        generation = metadata.get("generation_settings")
        if not isinstance(generation, str):
            generation = json.dumps(generation or {}, sort_keys=True)
        self._conn.execute(
            """
            INSERT INTO runs (
                run_id, created_at, config_name, dataset_name, dataset_version,
                model_name, model_digest, prompt_version, embedding_model,
                index_version, semgrep_version, semgrep_config, generation_settings,
                decision_threshold, git_commit, notes, status
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                run_id,
                utcnow(),
                metadata["config_name"],
                metadata.get("dataset_name"),
                metadata.get("dataset_version"),
                metadata.get("model_name"),
                metadata.get("model_digest"),
                metadata.get("prompt_version"),
                metadata.get("embedding_model"),
                metadata.get("index_version"),
                metadata.get("semgrep_version"),
                metadata.get("semgrep_config"),
                generation,
                metadata.get("decision_threshold"),
                metadata.get("git_commit"),
                metadata.get("notes"),
                "running",
            ),
        )
        self._conn.commit()

    def finish_run(self, run_id: str, status: str = "completed") -> None:
        self._conn.execute(
            "UPDATE runs SET status = ? WHERE run_id = ?",
            (status, run_id),
        )
        self._conn.commit()

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            "SELECT * FROM runs WHERE run_id = ?", (run_id,)
        ).fetchone()
        return dict(row) if row else None

    def latest_run_id(self) -> str | None:
        row = self._conn.execute(
            "SELECT run_id FROM runs ORDER BY created_at DESC LIMIT 1"
        ).fetchone()
        return row["run_id"] if row else None

    def existing_sample_ids(self, run_id: str) -> set[str]:
        rows = self._conn.execute(
            "SELECT sample_id FROM predictions WHERE run_id = ?",
            (run_id,),
        ).fetchall()
        return {r["sample_id"] for r in rows}

    def find_cached(self, cache_key: str) -> dict[str, Any] | None:
        row = self._conn.execute(
            """
            SELECT * FROM predictions
            WHERE cache_key = ? AND status = 'success'
            ORDER BY id DESC LIMIT 1
            """,
            (cache_key,),
        ).fetchone()
        return dict(row) if row else None

    def insert_prediction(self, record: dict[str, Any]) -> int:
        columns = [
            "run_id",
            "sample_id",
            "config_name",
            "cache_key",
            "created_at",
            "started_at",
            "ended_at",
            "latency_seconds",
            "ground_truth_label",
            "is_synthetic",
            "predicted_label",
            "model_predicted_label",
            "p_vulnerable",
            "decision_confidence",
            "predicted_cwe",
            "reasoning",
            "evidence",
            "limitations",
            "retrieved_json",
            "scan_json",
            "prompt_json",
            "raw_response",
            "status",
            "error",
            "prompt_eval_count",
            "eval_count",
            "reused_from",
        ]
        values = [record.get(col) for col in columns]
        if record.get("created_at") is None:
            values[columns.index("created_at")] = utcnow()
        placeholders = ",".join("?" for _ in columns)
        cur = self._conn.execute(
            f"INSERT INTO predictions ({','.join(columns)}) VALUES ({placeholders})",
            values,
        )
        self._conn.commit()
        return int(cur.lastrowid)

    def save_metrics(self, run_id: str, config_name: str, payload: dict[str, Any]) -> None:
        self._conn.execute(
            "INSERT INTO metrics (run_id, config_name, created_at, payload) VALUES (?, ?, ?, ?)",
            (run_id, config_name, utcnow(), json.dumps(payload, default=str)),
        )
        self._conn.commit()

    def predictions_for_run(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM predictions WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        return [dict(r) for r in rows]

    def latest_metrics(self, run_id: str) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM metrics WHERE run_id = ? ORDER BY id",
            (run_id,),
        ).fetchall()
        out = []
        for row in rows:
            item = dict(row)
            item["payload"] = json.loads(item["payload"])
            out.append(item)
        return out

    def list_runs(self, limit: int = 20) -> list[dict[str, Any]]:
        rows = self._conn.execute(
            "SELECT * FROM runs ORDER BY created_at DESC LIMIT ?",
            (limit,),
        ).fetchall()
        return [dict(r) for r in rows]


def export_predictions_jsonl(rows: Iterable[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for row in rows:
            handle.write(json.dumps(dict(row), default=str) + "\n")


def export_predictions_csv(rows: list[dict[str, Any]], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        path.write_text("")
        return
    fieldnames = list(rows[0].keys())
    with path.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow({k: row.get(k) for k in fieldnames})
