from __future__ import annotations

import hashlib
import json
import random
from collections import Counter
from pathlib import Path
from typing import Any, Iterable

from vulntriage.schemas import CanonicalSample, normalize_binary_label


def _as_cwe(value: Any) -> str | None:
    if value is None:
        return None
    if isinstance(value, list):
        if not value:
            return None
        return _as_cwe(value[0])
    text = str(value).strip()
    if not text:
        return None
    if text.isdigit():
        return f"CWE-{text}"
    if text.upper().startswith("CWE-"):
        return text.upper() if text.count("-") == 1 else text
    return text


def detect_format(record: dict[str, Any]) -> str:
    keys = set(record.keys())
    if {"func", "target"} <= keys:
        return "primevul"
    if {"sample_id", "code", "label"} <= keys:
        return "canonical"
    if {"code", "label"} <= keys or {"func", "label"} <= keys:
        return "generic"
    return "unknown"


def from_primevul(record: dict[str, Any], *, split: str | None, source: str) -> CanonicalSample:
    cwes = record.get("cwe") or record.get("cwe_id")
    idx = record.get("idx", record.get("sample_id"))
    func_hash = record.get("func_hash")
    sample_id = str(idx) if idx is not None else None
    if sample_id is None:
        digest = hashlib.sha256(str(record.get("func", "")).encode()).hexdigest()[:16]
        sample_id = f"primevul-{digest}"
    return CanonicalSample(
        sample_id=f"{source}:{sample_id}",
        code=record["func"],
        label=normalize_binary_label(record.get("target", record.get("label"))),
        source_dataset=source,
        cwe_id=_as_cwe(cwes),
        cve_id=record.get("cve") or record.get("cve_id"),
        project_id=record.get("project") or record.get("project_id"),
        commit_hash=record.get("commit_id") or record.get("commit_hash"),
        split=split or record.get("split"),
        language=record.get("language"),
        file_name=record.get("file_name"),
        func_hash=str(func_hash) if func_hash is not None else None,
        is_synthetic=False,
        extra={
            k: record.get(k)
            for k in ("project_url", "commit_url", "nvd_url", "file_hash")
            if record.get(k) is not None
        },
    )


def from_generic(record: dict[str, Any], *, split: str | None, source: str) -> CanonicalSample:
    code = record.get("code") or record.get("func") or record.get("function")
    if not code:
        raise ValueError("record is missing code/func")
    label_raw = record.get("label", record.get("target"))
    sample_id = str(
        record.get("sample_id")
        or record.get("id")
        or record.get("idx")
        or hashlib.sha256(str(code).encode()).hexdigest()[:16]
    )
    is_synthetic = bool(record.get("is_synthetic", source.startswith("synthetic")))
    return CanonicalSample(
        sample_id=sample_id,
        code=str(code),
        label=normalize_binary_label(label_raw),
        source_dataset=record.get("source_dataset") or source,
        cwe_id=_as_cwe(record.get("cwe_id") or record.get("cwe")),
        cve_id=record.get("cve_id") or record.get("cve"),
        project_id=record.get("project_id") or record.get("project"),
        commit_hash=record.get("commit_hash") or record.get("commit_id"),
        split=split or record.get("split"),
        language=record.get("language"),
        file_name=record.get("file_name"),
        func_hash=str(record["func_hash"]) if record.get("func_hash") is not None else None,
        is_synthetic=is_synthetic,
        notes=record.get("notes"),
        extra=record.get("extra") or {},
    )


def convert_record(record: dict[str, Any], *, split: str | None, source: str) -> CanonicalSample:
    fmt = detect_format(record)
    if fmt == "primevul":
        return from_primevul(record, split=split, source=source)
    if fmt in {"canonical", "generic"}:
        return from_generic(record, split=split, source=source)
    raise ValueError(f"Unrecognized record schema; keys={sorted(record.keys())[:20]}")


def iter_json_records(path: Path) -> Iterable[dict[str, Any]]:
    if path.is_dir():
        files = sorted(path.glob("*.jsonl")) + sorted(path.glob("*.json"))
        for file in files:
            yield from iter_json_records(file)
        return
    text = path.read_text(encoding="utf-8").strip()
    if not text:
        return
    if path.suffix == ".jsonl" or "\n" in text and text.lstrip().startswith("{"):
        for line_no, line in enumerate(text.splitlines(), start=1):
            line = line.strip()
            if not line:
                continue
            try:
                obj = json.loads(line)
            except json.JSONDecodeError as exc:
                raise ValueError(f"{path}:{line_no} JSON error: {exc}") from exc
            if isinstance(obj, dict):
                yield obj
        return
    obj = json.loads(text)
    if isinstance(obj, list):
        for item in obj:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(obj, dict):
        for key in ("records", "data", "samples"):
            if isinstance(obj.get(key), list):
                for item in obj[key]:
                    if isinstance(item, dict):
                        yield item
                return
        yield obj


def infer_split_from_name(path: Path) -> str | None:
    name = path.name.lower()
    for split in ("train", "valid", "validation", "val", "test", "dev", "smoke", "pilot"):
        if split in name:
            if split in {"valid", "validation", "val"}:
                return "validation"
            return split
    return None


def import_dataset(
    input_path: str | Path,
    *,
    source_dataset: str | None = None,
    split: str | None = None,
) -> tuple[list[CanonicalSample], dict[str, Any]]:
    path = Path(input_path)
    if not path.exists():
        raise FileNotFoundError(
            f"Dataset not found: {path}. Provide a PrimeVul JSONL (or directory) "
            "via `vulntriage benchmark import --input PATH`."
        )
    source = source_dataset or path.stem
    samples: list[CanonicalSample] = []
    errors: list[str] = []
    files = [path] if path.is_file() else sorted(
        list(path.glob("*.jsonl")) + list(path.glob("*.json"))
    )
    if not files:
        raise ValueError(f"No JSON/JSONL files under {path}")
    for file in files:
        file_split = split or infer_split_from_name(file)
        for i, record in enumerate(iter_json_records(file), start=1):
            try:
                samples.append(
                    convert_record(record, split=file_split, source=source)
                )
            except Exception as exc:
                errors.append(f"{file.name}:{i}: {exc}")
    unique, dropped = deduplicate(samples)
    report = {
        "input": str(path),
        "source_dataset": source,
        "n_read": len(samples),
        "n_unique": len(unique),
        "n_dropped_duplicates": dropped,
        "n_errors": len(errors),
        "errors_preview": errors[:20],
        "class_distribution": class_distribution(unique),
        "synthetic_count": sum(1 for s in unique if s.is_synthetic),
        "splits": dict(Counter(s.split or "unspecified" for s in unique)),
        "label_definition": "1 = vulnerable, 0 = benign",
        "selection_method": "import all parseable records; exact-code+id deduplication",
        "exclusions": "records that failed schema conversion",
        "leakage_note": (
            "If samples include CVE identifiers, retrieval must exclude those CVE "
            "records. Overlap with NVD descriptions cannot be fully ruled out."
        ),
    }
    return unique, report


def deduplicate(samples: list[CanonicalSample]) -> tuple[list[CanonicalSample], int]:
    seen: set[str] = set()
    out: list[CanonicalSample] = []
    dropped = 0
    for sample in samples:
        key = hashlib.sha256(
            f"{sample.source_dataset}|{sample.sample_id}|{sample.code}".encode()
        ).hexdigest()
        if key in seen:
            dropped += 1
            continue
        seen.add(key)
        out.append(sample)
    return out, dropped


def class_distribution(samples: Iterable[CanonicalSample]) -> dict[str, int]:
    counts = Counter(s.label for s in samples)
    return {"vulnerable": counts.get(1, 0), "benign": counts.get(0, 0)}


def write_jsonl(samples: Iterable[CanonicalSample], path: Path) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("w", encoding="utf-8") as handle:
        for sample in samples:
            handle.write(sample.model_dump_json() + "\n")


def load_jsonl(path: Path) -> list[CanonicalSample]:
    samples: list[CanonicalSample] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                samples.append(CanonicalSample.model_validate_json(line))
    return samples


def select_pilot(
    samples: list[CanonicalSample],
    *,
    limit: int,
    seed: int,
    split: str | None = None,
    include_synthetic: bool = False,
    stratify: bool = True,
) -> list[CanonicalSample]:
    pool = [
        s
        for s in samples
        if (include_synthetic or not s.is_synthetic)
        and (split is None or s.split == split)
    ]
    if not pool:
        pool = list(samples)
    rng = random.Random(seed)
    if not stratify or limit >= len(pool):
        chosen = list(pool)
        rng.shuffle(chosen)
        return chosen[:limit]
    by_label: dict[int, list[CanonicalSample]] = {0: [], 1: []}
    for sample in pool:
        by_label.setdefault(sample.label, []).append(sample)
    for bucket in by_label.values():
        rng.shuffle(bucket)
    per_class = max(1, limit // 2)
    selected: list[CanonicalSample] = []
    for label in (0, 1):
        selected.extend(by_label.get(label, [])[:per_class])
    leftover = [s for s in pool if s not in selected]
    rng.shuffle(leftover)
    while len(selected) < limit and leftover:
        selected.append(leftover.pop())
    rng.shuffle(selected)
    return selected[:limit]


def sample_prompt_payload(sample: CanonicalSample) -> dict[str, Any]:
    """Fields allowed in model-facing prompts. No labels or hidden answers."""
    return {
        "sample_id": sample.sample_id,
        "code": sample.code,
        "language": sample.language,
        "file_name": sample.file_name,
    }
