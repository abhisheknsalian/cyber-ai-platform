"""Phase 11: read-only evaluation and benchmarking layer for the existing platform.

Nothing in this package trains, retrains, or modifies the production model, the real
dataset, the vector store, or the threat graph. It only loads and measures what
already exists. See backend/evaluation/__main__.py for the CLI entry point
(`uv run python -m backend.evaluation`) and README "Evaluation & Benchmarking" for the
full methodology and its limitations.
"""
