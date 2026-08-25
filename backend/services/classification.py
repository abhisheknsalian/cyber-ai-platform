from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence
from backend.intelligence.schemas import ClassifierEvidence, HybridEvidence
from backend.ml.schemas import ClassificationAnalysisRequest, ClassificationResult
from backend.models.schemas import ThreatAnalysis
from backend.services.threat_analysis import analyze_query

# The classifier is binary (BENIGN/DDoS), so these mappings are currently a single
# entry each. The query text is the same sample query already proven (Phase 2
# relevance testing) to retrieve the ddos_attack.txt knowledge-base document well
# within the relevance threshold. PREDICTION_TO_THREAT_STEM (Phase 9) is the same
# mapping expressed as a threat-graph stem, used to attach graph evidence directly
# rather than inferring it from vector retrieval's own top match.
PREDICTION_TO_QUERY = {
    "DDoS": "How can DDoS attacks be mitigated?",
}
PREDICTION_TO_THREAT_STEM = {
    "DDoS": "ddos_attack",
}


class UnsupportedPredictionError(ValueError):
    """Raised when a prediction has no corresponding threat-intelligence mapping."""


def classify_and_analyze(
    request: ClassificationAnalysisRequest,
) -> tuple[ClassificationResult, ThreatAnalysis | None, HybridEvidence | None]:
    """Map a classifier prediction to a RAG threat analysis, plus (Phase 9) the
    hybrid evidence bundle backing that analysis -- classifier prediction/probability,
    vector matches, and graph relationships, so the response can answer "why did the
    system reach this conclusion?" (see README "Source Attribution").

    BENIGN is a valid prediction but not a threat -- returns (classification, None,
    None) rather than fabricating a threat report or evidence for traffic that wasn't
    classified as malicious.

    The classifier's prediction/probability are read from `request` (the Random
    Forest's own output, computed and validated before this function is ever called --
    see POST /classify and backend/ml/predictor.py) and are never re-derived from or
    editable by the LLM: analyze_query()'s LLMAnalysisFragment schema has no
    prediction/probability field at all, so there is no field for the model to
    override them with even if it tried.
    """
    classification = ClassificationResult(
        prediction=request.prediction,
        probability=request.probability,
        model="random_forest",
        # Generalizes beyond a DDoS-specific check, matching backend/ml/predictor.py's
        # predict(): any non-BENIGN prediction is "malicious". Behaviorally identical
        # to the old `== "DDoS"` check given the two labels LABEL_MAP currently has.
        classification="malicious" if request.prediction != "BENIGN" else "benign",
    )

    if request.prediction == "BENIGN":
        return classification, None, None

    query = PREDICTION_TO_QUERY.get(request.prediction)
    threat_stem = PREDICTION_TO_THREAT_STEM.get(request.prediction)
    if query is None or threat_stem is None:
        raise UnsupportedPredictionError(
            f"No threat-intelligence mapping exists for prediction {request.prediction!r}"
        )

    classifier_evidence = ClassifierEvidence(
        prediction=classification.prediction,
        probability=classification.probability,
        model=classification.model,
    )

    analysis = analyze_query(query, classifier=classifier_evidence)

    # A second, small vector search (see gather_hybrid_evidence) beyond the one
    # analyze_query() already performs internally -- a deliberate, cheap (millisecond-
    # scale, no LLM involved) duplication rather than changing analyze_query()'s
    # return type, which POST /analyze also depends on unchanged. See README
    # "Performance" for a measured cost.
    evidence = gather_hybrid_evidence(query, threat_hint=threat_stem, classifier=classifier_evidence)

    return classification, analysis, evidence
