"""Grounding / hallucination-proxy check (Phase 16, Part F).

Defines a measurable, automated proxy for "does the generated analysis stay grounded
in retrieved evidence" -- explicitly NOT a claim of "zero hallucinations" and NOT true
claim-level fact verification (that would need an entailment/NLI model or human
annotation, neither of which this module has). The methodology:

1. For each analyzed case, `attack_vectors` (the LLM's own short, discrete phrases --
   see backend/evaluation/llm_evaluation.py's module docstring for why this is the
   right target: summary/indicators/mitigations are either too free-form for reliable
   automated extraction or not actually LLM-generated in this architecture) are
   treated as "claims".
2. Each claim is checked for LEXICAL overlap against the actual retrieved context text
   the LLM was given (re-fetched via the same production retrieve_relevant() call
   analyze_query() itself makes -- no new retrieval logic).
3. A claim is "supported" if a sufficient fraction of its significant (non-stopword)
   words appear in that context text, case-insensitively.

This is a coarse heuristic with known failure modes in both directions: a paraphrased
but genuinely grounded claim can score unsupported (false negative -- no synonym
matching), and a claim sharing common words with the context by coincidence can score
supported (false positive -- no semantic verification). It is reported as
`supported_ratio`, never as "hallucination rate" or "grounding accuracy". A rigorous
claim-level grounding audit is a human-evaluation task; this module does not attempt
to replace one.
"""

from __future__ import annotations

import re

from backend.evaluation.llm_evaluation import DEFAULT_CASES
from backend.evaluation.schemas import GroundingQueryResult, GroundingReport
from backend.rag.config import RAG_SCORE_THRESHOLD, RAG_TOP_K
from backend.rag.retrieval import retrieve_relevant, vector_store_available
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.threat_analysis import analyze_query

_STOPWORDS = {
    "a", "an", "and", "are", "as", "at", "be", "by", "for", "from", "has", "in",
    "into", "is", "it", "of", "on", "or", "that", "the", "this", "to", "was",
    "were", "with", "via", "using", "used", "can", "may", "through", "over",
}
_WORD_PATTERN = re.compile(r"[a-z0-9]+")
_SUPPORT_THRESHOLD = 0.4  # fraction of a claim's significant words that must appear in context


class GroundingEvaluationUnavailableError(RuntimeError):
    """Raised when the vector store isn't available -- never fabricates a grounding result."""


def _significant_words(text: str) -> set[str]:
    return {word for word in _WORD_PATTERN.findall(text.lower()) if word not in _STOPWORDS and len(word) > 2}


def _is_supported(claim: str, context_words: set[str]) -> bool:
    claim_words = _significant_words(claim)
    if not claim_words:
        return False
    overlap = len(claim_words & context_words)
    return (overlap / len(claim_words)) >= _SUPPORT_THRESHOLD


def _retrieved_context_text(query: str, primary_threat: str | None) -> str:
    relevant = retrieve_relevant(query, k=RAG_TOP_K, threshold=RAG_SCORE_THRESHOLD)
    if primary_threat is not None:
        relevant = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == primary_threat]
    return "\n\n".join(doc.page_content for doc, _score in relevant)


def run_grounding_evaluation(cases: list[tuple[str, str | None]] | None = None) -> GroundingReport:
    if not vector_store_available():
        raise GroundingEvaluationUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    cases = cases if cases is not None else [c for c in DEFAULT_CASES if c[1] is not None]

    per_query: list[GroundingQueryResult] = []
    for query, expected_category in cases:
        try:
            result = analyze_query(query)
        except (LLMUnavailableError, LLMResponseError):
            continue
        if result.status != "analyzed" or not result.attack_vectors:
            per_query.append(
                GroundingQueryResult(
                    query=query, category=expected_category or "(negative control)", claims_checked=0,
                    claims_supported=0, supported_ratio=None,
                )
            )
            continue

        context_text = _retrieved_context_text(query, result.threat)
        context_words = _significant_words(context_text)

        supported = sum(1 for claim in result.attack_vectors if _is_supported(claim, context_words))
        total = len(result.attack_vectors)
        per_query.append(
            GroundingQueryResult(
                query=query,
                category=expected_category or "(negative control)",
                claims_checked=total,
                claims_supported=supported,
                supported_ratio=round(supported / total, 6) if total else None,
            )
        )

    scored = [q.supported_ratio for q in per_query if q.supported_ratio is not None]
    mean_ratio = round(sum(scored) / len(scored), 6) if scored else None

    return GroundingReport(
        cases_evaluated=len(per_query),
        mean_supported_ratio=mean_ratio,
        per_query=per_query,
        methodology_note=(
            f"Coarse lexical-overlap proxy, not fact verification: an attack_vectors "
            f"claim is 'supported' if >= {_SUPPORT_THRESHOLD:.0%} of its significant "
            "words appear in the actual retrieved context text for that query. "
            "Known failure modes: paraphrased-but-grounded claims can score "
            "unsupported (no synonym matching); claims sharing common words with the "
            "context by coincidence can score supported (no semantic verification). "
            "Report as 'supported_ratio', never as a hallucination rate or accuracy "
            "figure. A rigorous claim-level audit requires human annotation or an "
            "entailment model, neither implemented here."
        ),
    )
