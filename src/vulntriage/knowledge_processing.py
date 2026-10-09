from __future__ import annotations

import json
import sys
from pathlib import Path
from typing import Iterable, Iterator
from xml.etree import ElementTree as ET

from vulntriage.schemas import KnowledgeDocument

CWE_NS = {"cwe": "http://cwe.mitre.org/cwe-7"}
CAPEC_NS = {"capec": "http://capec.mitre.org/capec-3"}


def local(tag: str) -> str:
    return tag.rsplit("}", 1)[-1]


def text_of(element: ET.Element | None) -> str:
    if element is None:
        return ""
    parts = [element.text or ""]
    for child in list(element):
        parts.append(text_of(child))
        parts.append(child.tail or "")
    return " ".join(" ".join(parts).split())


def iter_nvd_documents(path: Path) -> Iterator[KnowledgeDocument]:
    print(f"[nvd] loading {path} ...", file=sys.stderr)
    with path.open(encoding="utf-8") as handle:
        payload = json.load(handle)
    version = str(payload.get("version") or "2.0")
    items = payload.get("vulnerabilities") or []
    print(f"[nvd] {path.name}: {len(items)} records", file=sys.stderr)
    kept = 0
    skipped = 0
    for item in items:
        cve = item.get("cve") or {}
        cve_id = cve.get("id")
        status = (cve.get("vulnStatus") or "").lower()
        if not cve_id:
            skipped += 1
            continue
        if status == "rejected":
            skipped += 1
            continue
        descriptions = cve.get("descriptions") or []
        english = next(
            (d.get("value") for d in descriptions if d.get("lang") == "en" and d.get("value")),
            None,
        )
        if not english:
            skipped += 1
            continue
        weaknesses: list[str] = []
        for block in cve.get("weaknesses") or []:
            for desc in block.get("description") or []:
                value = (desc.get("value") or "").strip()
                if value:
                    weaknesses.append(value)
        refs = []
        for ref in (cve.get("references") or [])[:8]:
            url = ref.get("url")
            if url:
                refs.append(url)
        kept += 1
        yield KnowledgeDocument(
            document_id=f"nvd:{cve_id}",
            source="NVD",
            source_version=version,
            identifier=cve_id,
            title=cve_id,
            description=english,
            relationships=sorted(set(weaknesses)),
            references=refs,
            extra={
                "vulnStatus": cve.get("vulnStatus"),
                "published": cve.get("published"),
                "file": path.name,
            },
        )
    print(f"[nvd] {path.name}: kept={kept} skipped={skipped}", file=sys.stderr)


def iter_cwe_documents(path: Path) -> Iterator[KnowledgeDocument]:
    print(f"[cwe] parsing {path} ...", file=sys.stderr)
    tree = ET.parse(path)
    root = tree.getroot()
    version = root.attrib.get("Version") or "unknown"
    weaknesses = root.findall("cwe:Weaknesses/cwe:Weakness", CWE_NS)
    if not weaknesses:
        weaknesses = [el for el in root.iter() if local(el.tag) == "Weakness"]
    print(f"[cwe] weaknesses found: {len(weaknesses)}", file=sys.stderr)
    for node in weaknesses:
        cwe_id = node.attrib.get("ID")
        name = node.attrib.get("Name") or ""
        if not cwe_id:
            continue
        identifier = f"CWE-{cwe_id}"
        description_el = None
        for child in node:
            if local(child.tag) == "Description":
                description_el = child
                break
        description = text_of(description_el) or name
        relationships: list[str] = []
        for rel in node.iter():
            if local(rel.tag) == "Related_Weakness":
                other = rel.attrib.get("CWE_ID")
                nature = rel.attrib.get("Nature")
                if other:
                    relationships.append(f"{nature or 'related'}:CWE-{other}")
        yield KnowledgeDocument(
            document_id=f"cwe:{identifier}",
            source="CWE",
            source_version=version,
            identifier=identifier,
            title=f"{identifier}: {name}".strip(": "),
            description=description,
            relationships=relationships[:20],
            extra={"abstraction": node.attrib.get("Abstraction")},
        )


def iter_capec_documents(path: Path) -> Iterator[KnowledgeDocument]:
    print(f"[capec] parsing {path} ...", file=sys.stderr)
    tree = ET.parse(path)
    root = tree.getroot()
    version = root.attrib.get("Version") or "unknown"
    patterns = root.findall("capec:Attack_Patterns/capec:Attack_Pattern", CAPEC_NS)
    if not patterns:
        patterns = [el for el in root.iter() if local(el.tag) == "Attack_Pattern"]
    print(f"[capec] attack patterns found: {len(patterns)}", file=sys.stderr)
    for node in patterns:
        capec_id = node.attrib.get("ID")
        name = node.attrib.get("Name") or ""
        if not capec_id:
            continue
        identifier = f"CAPEC-{capec_id}"
        description_el = None
        for child in node:
            if local(child.tag) == "Description":
                description_el = child
                break
        description = text_of(description_el) or name
        relationships: list[str] = []
        for rel in node.iter():
            tag = local(rel.tag)
            if tag == "Related_Weakness" and rel.attrib.get("CWE_ID"):
                relationships.append(f"CWE-{rel.attrib['CWE_ID']}")
            if tag == "Related_Attack_Pattern" and rel.attrib.get("CAPEC_ID"):
                nature = rel.attrib.get("Nature") or "related"
                relationships.append(f"{nature}:CAPEC-{rel.attrib['CAPEC_ID']}")
        yield KnowledgeDocument(
            document_id=f"capec:{identifier}",
            source="CAPEC",
            source_version=version,
            identifier=identifier,
            title=f"{identifier}: {name}".strip(": "),
            description=description,
            relationships=sorted(set(relationships))[:20],
            extra={"status": node.attrib.get("Status")},
        )


def discover_raw_files(raw_dir: Path) -> dict[str, list[Path]]:
    nvd = sorted(raw_dir.glob("**/nvdcve-2.0-*.json"))
    cwe = sorted(raw_dir.glob("**/cwec_*.xml"))
    capec = sorted(raw_dir.glob("**/capec_*.xml"))
    return {"nvd": nvd, "cwe": cwe, "capec": capec}


def normalize_knowledge(
    raw_dir: Path,
    out_path: Path,
    *,
    sources: Iterable[str] | None = None,
) -> dict[str, int]:
    wanted = set(sources or ("nvd", "cwe", "capec"))
    files = discover_raw_files(raw_dir)
    if not any(files.values()):
        raise FileNotFoundError(
            f"No NVD/CWE/CAPEC files under {raw_dir}. "
            "Point paths.raw_data_dir at the downloaded files; do not modify them."
        )
    out_path.parent.mkdir(parents=True, exist_ok=True)
    counts = {"nvd": 0, "cwe": 0, "capec": 0, "written": 0}
    with out_path.open("w", encoding="utf-8") as handle:
        if "nvd" in wanted:
            for path in files["nvd"]:
                try:
                    for doc in iter_nvd_documents(path):
                        handle.write(doc.model_dump_json() + "\n")
                        counts["nvd"] += 1
                        counts["written"] += 1
                except Exception as exc:
                    print(f"[nvd] ERROR processing {path}: {exc}", file=sys.stderr)
                    raise
        if "cwe" in wanted:
            for path in files["cwe"]:
                try:
                    for doc in iter_cwe_documents(path):
                        handle.write(doc.model_dump_json() + "\n")
                        counts["cwe"] += 1
                        counts["written"] += 1
                except Exception as exc:
                    print(f"[cwe] ERROR processing {path}: {exc}", file=sys.stderr)
                    raise
        if "capec" in wanted:
            for path in files["capec"]:
                try:
                    for doc in iter_capec_documents(path):
                        handle.write(doc.model_dump_json() + "\n")
                        counts["capec"] += 1
                        counts["written"] += 1
                except Exception as exc:
                    print(f"[capec] ERROR processing {path}: {exc}", file=sys.stderr)
                    raise
    print(f"[normalize] wrote {counts['written']} documents to {out_path}", file=sys.stderr)
    return counts


def load_documents(path: Path) -> list[KnowledgeDocument]:
    docs: list[KnowledgeDocument] = []
    with path.open(encoding="utf-8") as handle:
        for line in handle:
            line = line.strip()
            if line:
                docs.append(KnowledgeDocument.model_validate_json(line))
    return docs
