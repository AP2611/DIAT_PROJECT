from __future__ import annotations

import json
from pathlib import Path

import pytest

from tests.fakes import FakeOllama
from vulntriage.schemas import CanonicalSample


@pytest.fixture
def sample_vuln() -> CanonicalSample:
    return CanonicalSample(
        sample_id="t-vuln",
        code="query = f\"SELECT * FROM t WHERE id='{user}'\"",
        label=1,
        source_dataset="unit",
        cve_id="CVE-2024-0001",
        cwe_id="CWE-89",
        split="test",
        language="python",
        is_synthetic=False,
    )


@pytest.fixture
def sample_benign() -> CanonicalSample:
    return CanonicalSample(
        sample_id="t-benign",
        code="def add(a, b):\n    return a + b\n",
        label=0,
        source_dataset="unit",
        split="test",
        language="python",
        is_synthetic=False,
    )


@pytest.fixture
def fake_ollama() -> FakeOllama:
    return FakeOllama()


@pytest.fixture
def tiny_nvd(tmp_path: Path) -> Path:
    payload = {
        "format": "NVD_CVE",
        "version": "2.0",
        "vulnerabilities": [
            {
                "cve": {
                    "id": "CVE-2024-0001",
                    "vulnStatus": "Modified",
                    "descriptions": [
                        {"lang": "en", "value": "SQL injection in example app."}
                    ],
                    "weaknesses": [
                        {
                            "source": "nvd@nist.gov",
                            "type": "Primary",
                            "description": [{"lang": "en", "value": "CWE-89"}],
                        }
                    ],
                    "references": [{"url": "https://example.test/cve"}],
                }
            },
            {
                "cve": {
                    "id": "CVE-2024-9999",
                    "vulnStatus": "Rejected",
                    "descriptions": [{"lang": "en", "value": "Rejected reason: unused"}],
                }
            },
        ],
    }
    path = tmp_path / "nvdcve-2.0-2024.json"
    path.write_text(json.dumps(payload))
    return path
