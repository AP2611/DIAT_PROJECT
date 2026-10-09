from __future__ import annotations

import json
from pathlib import Path

import pytest

from vulntriage.dataset import import_dataset, normalize_binary_label, select_pilot
from vulntriage.schemas import CanonicalSample


def test_normalize_labels():
    assert normalize_binary_label("vulnerable") == 1
    assert normalize_binary_label("benign") == 0
    assert normalize_binary_label(1) == 1
    assert normalize_binary_label("0") == 0
    with pytest.raises(ValueError):
        normalize_binary_label("maybe")


def test_primevul_import(tmp_path: Path):
    path = tmp_path / "primevul_test.jsonl"
    records = [
        {
            "idx": 1,
            "project": "foo",
            "commit_id": "abc",
            "target": 1,
            "func": "void f() { gets(buf); }",
            "cwe": ["CWE-120"],
            "cve": "CVE-2020-1234",
            "file_name": "a.c",
        },
        {
            "idx": 1,
            "project": "foo",
            "commit_id": "abc",
            "target": 1,
            "func": "void f() { gets(buf); }",
            "cwe": ["CWE-120"],
            "cve": "CVE-2020-1234",
        },
        {
            "idx": 2,
            "project": "bar",
            "commit_id": "def",
            "target": 0,
            "func": "int add(int a, int b) { return a + b; }",
            "cwe": [],
            "cve": "",
        },
    ]
    path.write_text("\n".join(json.dumps(r) for r in records))
    samples, report = import_dataset(path, source_dataset="primevul")
    assert report["n_read"] == 3
    assert report["n_dropped_duplicates"] == 1
    assert report["class_distribution"] == {"vulnerable": 1, "benign": 1}
    vuln = next(s for s in samples if s.label == 1)
    assert vuln.cve_id == "CVE-2020-1234"
    assert vuln.cwe_id == "CWE-120"
    assert vuln.commit_hash == "abc"
    assert "gets" in vuln.code
    assert vuln.source_dataset == "primevul"


def test_canonical_roundtrip():
    sample = CanonicalSample.model_validate(
        {
            "sample_id": "x",
            "code": "a",
            "label": "1",
            "source_dataset": "unit",
            "cwe_id": ["CWE-79"],
        }
    )
    assert sample.label == 1
    assert sample.cwe_id == "CWE-79"


def test_pilot_is_deterministic():
    samples = [
        CanonicalSample(
            sample_id=f"s{i}",
            code=f"code{i}",
            label=i % 2,
            source_dataset="unit",
            split="test",
        )
        for i in range(20)
    ]
    a = [s.sample_id for s in select_pilot(samples, limit=6, seed=42)]
    b = [s.sample_id for s in select_pilot(samples, limit=6, seed=42)]
    c = [s.sample_id for s in select_pilot(samples, limit=6, seed=7)]
    assert a == b
    assert a != c
    labels = [s.label for s in select_pilot(samples, limit=6, seed=42)]
    assert 0 in labels and 1 in labels
