"""Builds the evidence-labeled context string passed into the existing LLM call
(backend/services/llm.py's generate_analysis_fragment(query, context) -- signature
unchanged) and derives the deterministic indicator/mitigation lists from graph
evidence. The LLM analysis layer itself is not replaced: this module only changes
what goes into its `context` argument, from a single block of raw retrieved text into
clearly labeled evidence sections, so the model can distinguish retrieved-text
evidence, graph evidence, and (when present) classifier evidence, instead of relying
on one undifferentiated string.

Pure functions, no I/O -- easy to unit test without Chroma/Ollama (see
tests/test_intelligence_evidence_context.py).
"""

from __future__ import annotations

from backend.intelligence.schemas import ClassifierEvidence, GraphEvidenceItem


def graph_derived_indicators(graph_evidence: list[GraphEvidenceItem]) -> list[str]:
    return [item.target_name for item in graph_evidence if item.relation == "HAS_INDICATOR"]


def graph_derived_mitigations(graph_evidence: list[GraphEvidenceItem]) -> list[str]:
    return [item.target_name for item in graph_evidence if item.relation == "MITIGATED_BY"]


def graph_derived_techniques(graph_evidence: list[GraphEvidenceItem]) -> list[str]:
    return [item.target_name for item in graph_evidence if item.relation == "USES"]


def build_evidence_context(
    *,
    retrieved_text: str,
    graph_evidence: list[GraphEvidenceItem],
    classifier: ClassifierEvidence | None = None,
) -> str:
    """Assembles the full context string. Every section is deterministically derived
    (retrieved chunk text from vector search, indicator/mitigation/technique names
    from the threat graph, classifier fields from the Random Forest's own output) --
    nothing here is LLM-generated, so nothing the LLM later writes can trace back to
    a fabricated evidence section."""
    sections = ["Retrieved Threat Intelligence Context:\n" + retrieved_text]

    indicators = graph_derived_indicators(graph_evidence)
    if indicators:
        sections.append(
            "Known Indicators (from the threat intelligence graph):\n"
            + "\n".join(f"- {name}" for name in indicators)
        )

    mitigations = graph_derived_mitigations(graph_evidence)
    if mitigations:
        sections.append(
            "Known Mitigations (from the threat intelligence graph):\n"
            + "\n".join(f"- {name}" for name in mitigations)
        )

    techniques = graph_derived_techniques(graph_evidence)
    if techniques:
        sections.append(
            "Known MITRE ATT&CK Techniques (from the threat intelligence graph -- for "
            "context only; technique IDs are attached to the response separately from "
            "verified source data, never from your output):\n"
            + "\n".join(f"- {name}" for name in techniques)
        )

    if classifier is not None:
        probability = "unknown" if classifier.probability is None else f"{classifier.probability:.2f}"
        sections.append(
            "Classifier Evidence (authoritative -- produced by a trained model before "
            "you were invoked; explain it, do not contradict or restate a different "
            "prediction):\n"
            f"- prediction: {classifier.prediction}\n"
            f"- probability: {probability}\n"
            f"- model: {classifier.model}"
        )

    return "\n\n".join(sections)
