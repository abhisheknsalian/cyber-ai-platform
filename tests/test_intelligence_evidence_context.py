"""Tests for backend/intelligence/evidence_context.py: pure evidence-formatting
functions, no Chroma/Ollama involved."""

from backend.intelligence.evidence_context import (
    build_evidence_context,
    graph_derived_indicators,
    graph_derived_mitigations,
    graph_derived_techniques,
)
from backend.intelligence.schemas import ClassifierEvidence, GraphEvidenceItem

DDOS_GRAPH_EVIDENCE = [
    GraphEvidenceItem(relation="SUPPORTED_BY", target_id="source:ddos_attack.txt", target_name="ddos_attack.txt", target_type="source"),
    GraphEvidenceItem(relation="USES", target_id="mitre:T1498", target_name="Network Denial of Service", target_type="technique"),
    GraphEvidenceItem(relation="HAS_INDICATOR", target_id="indicator:high_traffic", target_name="Extremely high traffic volume", target_type="indicator"),
    GraphEvidenceItem(relation="MITIGATED_BY", target_id="mitigation:rate_limiting", target_name="Rate limiting", target_type="mitigation"),
]


def test_graph_derived_indicators_filters_to_has_indicator_only():
    assert graph_derived_indicators(DDOS_GRAPH_EVIDENCE) == ["Extremely high traffic volume"]


def test_graph_derived_mitigations_filters_to_mitigated_by_only():
    assert graph_derived_mitigations(DDOS_GRAPH_EVIDENCE) == ["Rate limiting"]


def test_graph_derived_techniques_filters_to_uses_only():
    assert graph_derived_techniques(DDOS_GRAPH_EVIDENCE) == ["Network Denial of Service"]


def test_empty_graph_evidence_produces_empty_lists():
    assert graph_derived_indicators([]) == []
    assert graph_derived_mitigations([]) == []


def test_build_evidence_context_always_includes_retrieved_text():
    context = build_evidence_context(retrieved_text="some retrieved chunk text", graph_evidence=[])
    assert "some retrieved chunk text" in context
    assert "Retrieved Threat Intelligence Context:" in context


def test_build_evidence_context_labels_graph_sections_separately():
    context = build_evidence_context(retrieved_text="chunk text", graph_evidence=DDOS_GRAPH_EVIDENCE)
    assert "Known Indicators" in context
    assert "Extremely high traffic volume" in context
    assert "Known Mitigations" in context
    assert "Rate limiting" in context
    assert "Known MITRE ATT&CK Techniques" in context
    assert "Network Denial of Service" in context


def test_build_evidence_context_omits_empty_sections():
    context = build_evidence_context(retrieved_text="chunk text", graph_evidence=[])
    assert "Known Indicators" not in context
    assert "Known Mitigations" not in context
    assert "Known MITRE ATT&CK Techniques" not in context


def test_build_evidence_context_includes_classifier_section_when_present():
    classifier = ClassifierEvidence(prediction="DDoS", probability=0.98, model="random_forest")
    context = build_evidence_context(retrieved_text="chunk text", graph_evidence=[], classifier=classifier)
    assert "Classifier Evidence" in context
    assert "DDoS" in context
    assert "0.98" in context
    assert "random_forest" in context


def test_build_evidence_context_omits_classifier_section_when_absent():
    context = build_evidence_context(retrieved_text="chunk text", graph_evidence=[], classifier=None)
    assert "Classifier Evidence" not in context


def test_build_evidence_context_handles_missing_probability():
    classifier = ClassifierEvidence(prediction="DDoS", probability=None, model="random_forest")
    context = build_evidence_context(retrieved_text="chunk text", graph_evidence=[], classifier=classifier)
    assert "unknown" in context
