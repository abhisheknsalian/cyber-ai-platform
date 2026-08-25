"""Tests for backend/intelligence/graph_store.py: build/save/load persistence,
process-wide caching, and availability reporting."""

from pathlib import Path

from backend.intelligence.entities import Entity, ThreatGraph
from backend.intelligence.graph_store import build_graph, get_graph, graph_available, load_graph, save_graph


def test_build_graph_produces_a_non_empty_graph():
    graph = build_graph()
    assert len(graph.entities) > 0
    assert len(graph.relationships) > 0


def test_save_and_load_graph_round_trips(tmp_path: Path):
    graph = build_graph()
    path = save_graph(graph, path=tmp_path / "graph.json")
    assert path.exists()

    restored = load_graph(path=path)
    assert restored == graph


def test_save_graph_creates_parent_directories(tmp_path: Path):
    graph = ThreatGraph()
    graph.add_entity(Entity(id="threat:x", type="threat", name="X"))
    nested_path = tmp_path / "a" / "b" / "c" / "graph.json"

    save_graph(graph, path=nested_path)

    assert nested_path.exists()


def test_persisted_graph_is_readable_as_plain_json(tmp_path: Path):
    import json

    graph = build_graph()
    path = save_graph(graph, path=tmp_path / "graph.json")

    raw = json.loads(path.read_text(encoding="utf-8"))
    assert "entities" in raw
    assert "relationships" in raw


def test_get_graph_is_cached_across_calls():
    first = get_graph()
    second = get_graph()
    assert first is second  # same object -- proves the lru_cache singleton is active


def test_graph_available_is_true_for_the_real_knowledge_base():
    assert graph_available() is True
