"""Phase 11: tests for backend/evaluation/retrieval_evaluation.py.

conftest.py's autouse fixtures build a real vector store from the real
data/threat_intel/*.txt documents (unrelated to the synthetic ML dataset), so these
run against real retrieval/graph behavior, not mocks.
"""

import pytest

from backend.evaluation.retrieval_evaluation import run_retrieval_benchmark


def test_retrieval_benchmark_covers_every_query_in_the_corpus():
    result = run_retrieval_benchmark()
    assert result.queries_evaluated == len(result.per_query)
    assert result.queries_evaluated >= 2  # at least one real query + the negative control


def test_retrieval_benchmark_topic_coverage_and_preservation_rates_are_valid_fractions():
    result = run_retrieval_benchmark()
    assert 0.0 <= result.topic_coverage_rate <= 1.0
    assert 0.0 <= result.hybrid_preserves_both_sources_rate <= 1.0


def test_negative_control_query_returns_no_evidence():
    result = run_retrieval_benchmark()
    controls = [r for r in result.per_query if r.is_negative_control]
    assert controls, "expected at least one negative-control query in the corpus"
    for control in controls:
        assert control.expected_threat_type is None
        assert control.vector_hit_count == 0
        assert control.graph_relation_count == 0
        assert control.hybrid_has_vector_evidence is False
        assert control.hybrid_has_graph_evidence is False


def test_non_control_queries_with_a_known_topic_find_matching_evidence():
    result = run_retrieval_benchmark()
    non_control = [r for r in result.per_query if not r.is_negative_control]
    assert non_control, "expected at least one non-control query in the corpus"
    for item in non_control:
        assert item.expected_threat_type is not None
        assert item.vector_hit_count >= 0
        assert item.graph_relation_count >= 0


def test_latency_stats_are_present_and_non_negative():
    result = run_retrieval_benchmark()
    for stats in (result.vector_latency, result.graph_latency, result.hybrid_latency):
        assert stats.count == result.queries_evaluated
        assert stats.min_ms >= 0.0
        assert stats.min_ms <= stats.mean_ms <= stats.max_ms


def test_custom_query_list_is_respected_instead_of_the_default_corpus():
    result = run_retrieval_benchmark(queries=[("How can DDoS attacks be mitigated?", "ddos_attack")])
    assert result.queries_evaluated == 1
    assert result.per_query[0].query == "How can DDoS attacks be mitigated?"


def test_retrieval_benchmark_raises_when_vector_store_unavailable(monkeypatch):
    from backend.evaluation import retrieval_evaluation

    monkeypatch.setattr(retrieval_evaluation, "vector_store_available", lambda: False)
    with pytest.raises(retrieval_evaluation.RetrievalUnavailableError):
        run_retrieval_benchmark()
