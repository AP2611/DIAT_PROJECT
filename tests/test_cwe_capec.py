from __future__ import annotations

from pathlib import Path

from vulntriage.knowledge_processing import iter_capec_documents, iter_cwe_documents


def test_cwe_parser(tmp_path: Path):
    xml = """<?xml version="1.0"?>
<Weakness_Catalog xmlns="http://cwe.mitre.org/cwe-7" Version="4.20">
  <Weaknesses>
    <Weakness ID="89" Name="SQL Injection">
      <Description>Improper neutralization of SQL.</Description>
      <Related_Weaknesses>
        <Related_Weakness Nature="ChildOf" CWE_ID="74"/>
      </Related_Weaknesses>
    </Weakness>
  </Weaknesses>
</Weakness_Catalog>
"""
    path = tmp_path / "cwec_v4.20.xml"
    path.write_text(xml)
    docs = list(iter_cwe_documents(path))
    assert docs[0].identifier == "CWE-89"
    assert docs[0].source_version == "4.20"
    assert any("CWE-74" in r for r in docs[0].relationships)


def test_capec_parser(tmp_path: Path):
    xml = """<?xml version="1.0"?>
<Attack_Pattern_Catalog xmlns="http://capec.mitre.org/capec-3" Version="3.9">
  <Attack_Patterns>
    <Attack_Pattern ID="66" Name="SQL Injection">
      <Description>Adversary exploits SQL injection.</Description>
      <Related_Weaknesses>
        <Related_Weakness CWE_ID="89"/>
      </Related_Weaknesses>
    </Attack_Pattern>
  </Attack_Patterns>
</Attack_Pattern_Catalog>
"""
    path = tmp_path / "capec_v3.9.xml"
    path.write_text(xml)
    docs = list(iter_capec_documents(path))
    assert docs[0].identifier == "CAPEC-66"
    assert "CWE-89" in docs[0].relationships
