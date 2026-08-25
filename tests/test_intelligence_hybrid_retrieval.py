"""Tests for backend/intelligence/hybrid_retrieval.py: combining vector retrieval
(the existing backend/rag/retrieval.py, unmodified) with graph traversal into one
typed HybridEvidence object, and graph neighborhood lookups."""

from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence, graph_evidence_for_threat, graph_neighborhood
from backend.intelligence.schemas import ClassifierEvidence


def test_graph_evidence_for_threat_returns_relations_for_a_known_threat():
    evidence = graph_evidence_for_threat("ddos_attack")
    assert len(evidence) > 0
    assert any(item.relation == "USES" and item.target_name == "Network Denial of Service" for item in evidence)


def test_graph_evidence_for_threat_returns_empty_list_for_unknown_threat():
    assert graph_evidence_for_threat("not_a_real_threat") == []


def test_graph_neighborhood_returns_threat_and_relations():
    neighborhood = graph_neighborhood("ddos_attack")
    assert neighborhood is not None
    assert neighborhood.threat.name == "DDoS Attack"
    assert len(neighborhood.relations) > 0


def test_graph_neighborhood_returns_none_for_unknown_threat():
    assert graph_neighborhood("not_a_real_threat") is None


def test_gather_hybrid_evidence_combines_vector_and_graph_evidence():
    evidence = gather_hybrid_evidence("How can DDoS attacks be mitigated?")
    assert evidence.primary_threat == "ddos_attack"
    assert len(evidence.vector_evidence) > 0
    assert len(evidence.graph_evidence) > 0
    assert evidence.vector_duration_ms is not None
    assert evidence.graph_duration_ms is not None


def test_gather_hybrid_evidence_distinguishes_evidence_types():
    # The result must be a typed representation, not a concatenated string -- vector
    # and graph evidence stay in separate, independently-inspectable lists.
    evidence = gather_hybrid_evidence("How can DDoS attacks be mitigated?")
    assert isinstance(evidence.vector_evidence, list)
    assert isinstance(evidence.graph_evidence, list)
    assert evidence.vector_evidence != evidence.graph_evidence


def test_gather_hybrid_evidence_uses_threat_hint_when_given():
    # threat_hint overrides inferring the primary threat from vector retrieval's own
    # top match -- this is what lets the classifier path attach graph evidence for the
    # threat the classifier actually predicted, not just whatever vector search alone
    # would have surfaced.
    evidence = gather_hybrid_evidence("How can DDoS attacks be mitigated?", threat_hint="ddos_attack")
    assert evidence.primary_threat == "ddos_attack"
    assert len(evidence.graph_evidence) > 0


def test_gather_hybrid_evidence_carries_classifier_evidence_through_unmodified():
    classifier = ClassifierEvidence(prediction="DDoS", probability=0.98, model="random_forest")
    evidence = gather_hybrid_evidence("How can DDoS attacks be mitigated?", classifier=classifier)
    assert evidence.classifier == classifier
    assert evidence.classifier.prediction == "DDoS"
    assert evidence.classifier.probability == 0.98


def test_gather_hybrid_evidence_on_unrelated_query_has_no_graph_evidence():
    evidence = gather_hybrid_evidence("What is the capital of France?")
    assert evidence.vector_evidence == []
    assert evidence.graph_evidence == []
    assert evidence.primary_threat is None
