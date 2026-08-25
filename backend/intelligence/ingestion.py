"""uv run python -m backend.intelligence.ingestion

Builds the threat graph from data/threat_intel/*.txt and writes it to disk (see
GRAPH_STORE_PATH in graph_store.py). Not required for the graph to work -- get_graph()
builds and caches it in memory lazily on first access -- but useful for inspecting the
graph as a plain JSON file, or for pre-warming/verifying it outside a running server.

Deterministic: running this twice in a row produces byte-identical output (same
entity IDs, same relationships, same ordering), since build_graph_from_documents()
processes files in sorted order and every ID is derived from source text, never
randomly generated.
"""

from backend.intelligence.graph_store import build_graph, save_graph


def main() -> None:
    graph = build_graph()
    path = save_graph(graph)
    print(
        f"Threat graph written to {path}: "
        f"{len(graph.entities)} entities, {len(graph.relationships)} relationships"
    )


if __name__ == "__main__":
    main()
