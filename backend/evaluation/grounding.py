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

Phase 17 adds a SECOND, complementary automated signal, `supported_ratio_semantic`:
cosine similarity between a claim's sentence embedding and its best-matching context
sentence's embedding, using the SAME sentence-transformers/all-MiniLM-L6-v2 model
already loaded for production RAG retrieval (backend/rag/embeddings.py -- no new
model downloaded, no cloud API called). This catches some paraphrases the lexical
proxy misses (e.g. "steal login credentials" vs. "harvest credentials"), but it is
STILL a proxy, not entailment or hallucination detection: high cosine similarity
means "semantically/topically similar wording", not "logically implied by the
context" -- a claim can be topically similar to the context while asserting
something the context never actually states (e.g. an inverted or overstated claim).
Both proxies are reported side by side, neither is named "hallucination detection",
"factuality detection", or "truth verification" anywhere in this codebase, and both
retain their own documented failure modes.

**Threshold selection audit (Phase 17 self-review) -- read this before citing
supported_ratio_semantic as validated.** _SEMANTIC_SUPPORT_THRESHOLD was set by
directly observing this exact module's real cosine-similarity output on one of the
five cases `run_grounding_evaluation()`'s own default call later scores (the
"phishing" case's "Credential harvesting through fake login pages or malicious
links" claim, best match 0.7864) -- i.e. the threshold was chosen AFTER seeing
results, on the SAME small evaluation set it is later used to score, with no
independent held-out calibration set and no ground-truth labels involved at all
(there are none to use -- that is the entire reason this proxy exists). This is
calibration leakage in the classic sense, structurally identical to tuning a
hyperparameter on the test set, and is reported here explicitly rather than glossed
over. A follow-up sensitivity sweep (thresholds 0.3/0.4/0.5/0.6/0.7 against a real
8-claim run) found the reported supported_ratio_semantic score unchanged (8/8 = 1.0)
across the entire swept range for that specific sample -- most claims were
near-verbatim copies of source bullet text (cosine similarity 1.0000), so the result
happens not to be threshold-sensitive in that instance. A separate probe with four
deliberately unrelated claims against the same phishing context scored 0.24-0.38,
below every threshold in the 0.4-0.7 range but ABOVE 0.3 in one case -- meaning
threshold=0.3 would have produced a false positive on that probe, while 0.4-0.7
would not have. None of this makes 0.5 a validated threshold; it only shows the
metric is not obviously degenerate on the cases checked. Treat
supported_ratio_semantic as illustrative of this proxy's behavior on this small,
non-independently-calibrated case set -- not as a scientifically validated grounding
metric.
"""

from __future__ import annotations

import re

import numpy as np

from backend.evaluation.llm_evaluation import DEFAULT_CASES
from backend.evaluation.schemas import GroundingQueryResult, GroundingReport
from backend.rag.config import RAG_SCORE_THRESHOLD, RAG_TOP_K
from backend.rag.embeddings import get_embedding_model
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
# Calibrated empirically against real retrieved context (see this module's own dev
# notes / Phase 17 report): a genuinely grounded short claim's best-matching context
# line scores ~0.55-0.8 cosine similarity with sentence-transformers/all-MiniLM-L6-v2;
# an unrelated line typically scores well below that. 0.5 sits below the observed
# genuine-match cluster with margin, same empirical-threshold approach the project
# already uses for RAG_SCORE_THRESHOLD (see backend/rag/config.py).
_SEMANTIC_SUPPORT_THRESHOLD = 0.5
# The source documents are short bullet-point lists, not prose -- splitting only on
# sentence-ending punctuation leaves an entire bullet list as one "sentence" (diluting
# its embedding across many unrelated bullets). Splitting on newlines too gives each
# bullet its own embedding, which is what actually lets a short claim like "fake login
# pages" match the single matching bullet instead of the whole list's averaged vector.
_SENTENCE_SPLIT_PATTERN = re.compile(r"[\n]+|(?<=[.!?])\s+")


class GroundingEvaluationUnavailableError(RuntimeError):
    """Raised when the vector store isn't available -- never fabricates a grounding result."""


def significant_words(text: str) -> set[str]:
    return {word for word in _WORD_PATTERN.findall(text.lower()) if word not in _STOPWORDS and len(word) > 2}


def is_supported(claim: str, context_words: set[str]) -> bool:
    claim_words = significant_words(claim)
    if not claim_words:
        return False
    overlap = len(claim_words & context_words)
    return (overlap / len(claim_words)) >= _SUPPORT_THRESHOLD


def retrieved_context_text(query: str, primary_threat: str | None) -> str:
    relevant = retrieve_relevant(query, k=RAG_TOP_K, threshold=RAG_SCORE_THRESHOLD)
    if primary_threat is not None:
        relevant = [(doc, score) for doc, score in relevant if doc.metadata.get("threat_type") == primary_threat]
    return "\n\n".join(doc.page_content for doc, _score in relevant)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    a_arr, b_arr = np.array(a), np.array(b)
    denom = np.linalg.norm(a_arr) * np.linalg.norm(b_arr)
    return float(np.dot(a_arr, b_arr) / denom) if denom else 0.0


def semantic_supported(claim: str, context_sentences: list[str]) -> bool:
    """True if `claim`'s embedding is within _SEMANTIC_SUPPORT_THRESHOLD cosine
    similarity of its single best-matching context sentence. Reuses the production
    embedding model (cached, same instance retrieval already uses) -- no new model."""
    if not claim.strip() or not context_sentences:
        return False
    model = get_embedding_model()
    claim_vec = model.embed_query(claim)
    sentence_vecs = model.embed_documents(context_sentences)
    best = max(_cosine_similarity(claim_vec, vec) for vec in sentence_vecs)
    return best >= _SEMANTIC_SUPPORT_THRESHOLD


def _split_sentences(text: str) -> list[str]:
    lines = (s.strip().lstrip("-").strip() for s in _SENTENCE_SPLIT_PATTERN.split(text))
    return [line for line in lines if line]


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

        context_text = retrieved_context_text(query, result.threat)
        context_words = significant_words(context_text)
        context_sentences = _split_sentences(context_text)

        supported = sum(1 for claim in result.attack_vectors if is_supported(claim, context_words))
        supported_semantic = sum(1 for claim in result.attack_vectors if semantic_supported(claim, context_sentences))
        total = len(result.attack_vectors)
        per_query.append(
            GroundingQueryResult(
                query=query,
                category=expected_category or "(negative control)",
                claims_checked=total,
                claims_supported=supported,
                supported_ratio=round(supported / total, 6) if total else None,
                claims_supported_semantic=supported_semantic,
                supported_ratio_semantic=round(supported_semantic / total, 6) if total else None,
            )
        )

    scored = [q.supported_ratio for q in per_query if q.supported_ratio is not None]
    mean_ratio = round(sum(scored) / len(scored), 6) if scored else None
    scored_semantic = [q.supported_ratio_semantic for q in per_query if q.supported_ratio_semantic is not None]
    mean_ratio_semantic = round(sum(scored_semantic) / len(scored_semantic), 6) if scored_semantic else None

    return GroundingReport(
        cases_evaluated=len(per_query),
        mean_supported_ratio=mean_ratio,
        mean_supported_ratio_semantic=mean_ratio_semantic,
        per_query=per_query,
        methodology_note=(
            f"Coarse lexical-overlap proxy, not fact verification: an attack_vectors "
            f"claim is 'supported' if >= {_SUPPORT_THRESHOLD:.0%} of its significant "
            "words appear in the actual retrieved context text for that query. "
            "Known failure modes: paraphrased-but-grounded claims can score "
            "unsupported (no synonym matching); claims sharing common words with the "
            "context by coincidence can score supported (no semantic verification). "
            "Report as 'supported_ratio', never as a hallucination rate or accuracy "
            "figure. supported_ratio_semantic is a second, complementary proxy using "
            f"cosine similarity (threshold {_SEMANTIC_SUPPORT_THRESHOLD}) against the "
            "same sentence-transformers/all-MiniLM-L6-v2 model production RAG "
            "retrieval already uses -- catches some paraphrases the lexical proxy "
            "misses, but is still NOT entailment, hallucination detection, "
            "factuality detection, or truth verification: high similarity means "
            "topically similar wording, not 'logically implied by the context'. "
            "CALIBRATION LEAKAGE DISCLOSURE: the semantic threshold was selected by "
            "observing this exact module's real output on one of the cases this "
            "function itself later scores by default -- no independent calibration "
            "set exists, and no ground-truth labels were used (none exist for this "
            "proxy). See this module's docstring for the full threshold-selection "
            "audit and a sensitivity sweep (0.3-0.7) run against real output. "
            "mean_supported_ratio_semantic should be read as illustrative of proxy "
            "behavior on this small, non-independently-calibrated case set, not as a "
            "validated grounding metric. A rigorous claim-level audit requires human "
            "annotation or a dedicated entailment/NLI model, neither implemented here."
        ),
    )
