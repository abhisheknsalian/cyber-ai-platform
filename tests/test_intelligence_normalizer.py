"""Tests for backend/intelligence/normalizer.py: deterministic parsing of
data/threat_intel/*.txt into entities and relationships, and duplicate-ingestion
safety (running it twice must produce the same graph).
"""

from pathlib import Path

import pytest

from backend.intelligence.entities import mitigation_id, source_id, technique_id, threat_id
from backend.intelligence.normalizer import build_graph_from_documents, normalize_document
from backend.rag.config import THREAT_INTEL_DIR


@pytest.fixture(scope="module")
def real_graph():
    return build_graph_from_documents(THREAT_INTEL_DIR)


def test_normalize_ddos_document_extracts_threat_and_mitre_technique():
    entities, relationships = normalize_document(THREAT_INTEL_DIR / "ddos_attack.txt")
    entity_ids = {e.id for e in entities}
    assert threat_id("ddos_attack") in entity_ids
    assert technique_id("T1498") in entity_ids

    uses = [r for r in relationships if r.relation == "USES"]
    assert any(r.target_id == technique_id("T1498") for r in uses)


def test_normalize_extracts_indicators_and_mitigations_as_separate_entities():
    entities, relationships = normalize_document(THREAT_INTEL_DIR / "ddos_attack.txt")
    types_present = {e.type for e in entities}
    assert "indicator" in types_present
    assert "mitigation" in types_present

    mitigated_by = [r for r in relationships if r.relation == "MITIGATED_BY"]
    assert mitigation_id("Rate limiting") in {r.target_id for r in mitigated_by}


def test_every_relationship_has_a_reference_to_its_source_file():
    entities, relationships = normalize_document(THREAT_INTEL_DIR / "ddos_attack.txt")
    assert all(r.reference == "ddos_attack.txt" for r in relationships)


def test_source_entity_is_created_and_linked():
    entities, relationships = normalize_document(THREAT_INTEL_DIR / "phishing.txt")
    assert source_id("phishing.txt") in {e.id for e in entities}
    supported_by = [r for r in relationships if r.relation == "SUPPORTED_BY"]
    assert any(r.target_id == source_id("phishing.txt") for r in supported_by)


def test_normalizer_never_captures_unrelated_bulleted_sections():
    # ddos_attack.txt has a trailing "DDoS attacks are commonly used against:" bullet
    # list (websites, cloud infrastructure, ...) that is not an indicator or
    # mitigation section -- it must not leak into either.
    entities, _ = normalize_document(THREAT_INTEL_DIR / "ddos_attack.txt")
    names = {e.name.lower() for e in entities}
    assert "websites" not in names
    assert "cloud infrastructure" not in names


def test_mitigation_header_variants_are_all_recognized():
    # botnet.txt/ransomware.txt/sql_injection.txt say "Mitigation strategies:",
    # ddos_attack.txt says "Common mitigation strategies:", phishing.txt says
    # "Mitigation:" -- all three must be recognized as the same section type.
    for filename in ["botnet.txt", "ddos_attack.txt", "phishing.txt", "ransomware.txt", "sql_injection.txt"]:
        _, relationships = normalize_document(THREAT_INTEL_DIR / filename)
        assert any(r.relation == "MITIGATED_BY" for r in relationships), f"{filename} produced no MITIGATED_BY edges"


def test_build_graph_from_documents_includes_all_five_threats(real_graph):
    threat_names = {e.name for e in real_graph.entities.values() if e.type == "threat"}
    assert threat_names == {"Botnet", "DDoS Attack", "Phishing", "Ransomware", "SQL Injection"}


def test_build_graph_extracts_all_known_mitre_techniques(real_graph):
    technique_ids = {e.id for e in real_graph.entities.values() if e.type == "technique"}
    expected = {"mitre:T1584", "mitre:T1498", "mitre:T1566", "mitre:T1598", "mitre:T1486", "mitre:T1190"}
    assert expected <= technique_ids


def test_ingestion_is_deterministic_running_twice_produces_identical_graph():
    first = build_graph_from_documents(THREAT_INTEL_DIR)
    second = build_graph_from_documents(THREAT_INTEL_DIR)
    assert first == second


def test_ingestion_is_deterministic_across_serialization():
    first = build_graph_from_documents(THREAT_INTEL_DIR).model_dump_json()
    second = build_graph_from_documents(THREAT_INTEL_DIR).model_dump_json()
    assert first == second


def test_normalize_document_on_a_minimal_synthetic_file(tmp_path: Path):
    # Exercises the parser against a document outside the real knowledge base, so
    # this test doesn't depend on data/threat_intel/*.txt staying exactly as-is.
    doc = tmp_path / "synthetic_threat.txt"
    doc.write_text(
        "A synthetic threat for testing.\n\n"
        "Common indicators:\n- fake indicator one\n- fake indicator two\n\n"
        "MITRE ATT&CK Technique:\n- T9999: Synthetic Technique\n\n"
        "Mitigation strategies:\n- fake mitigation\n",
        encoding="utf-8",
    )
    entities, relationships = normalize_document(doc)
    assert threat_id("synthetic_threat") in {e.id for e in entities}
    assert technique_id("T9999") in {e.id for e in entities}
    assert len([e for e in entities if e.type == "indicator"]) == 2
    assert len([r for r in relationships if r.relation == "MITIGATED_BY"]) == 1
