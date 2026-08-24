from backend.ml.schemas import ClassificationAnalysisRequest, ClassificationResult
from backend.models.schemas import ThreatAnalysis
from backend.services.threat_analysis import analyze_query

# The classifier is binary (BENIGN/DDoS), so this mapping is currently a single entry.
# The query text is the same sample query already proven (Phase 2 relevance testing) to
# retrieve the ddos_attack.txt knowledge-base document well within the relevance threshold.
PREDICTION_TO_QUERY = {
    "DDoS": "How can DDoS attacks be mitigated?",
}


class UnsupportedPredictionError(ValueError):
    """Raised when a prediction has no corresponding threat-intelligence mapping."""


def classify_and_analyze(request: ClassificationAnalysisRequest) -> tuple[ClassificationResult, ThreatAnalysis | None]:
    """Map a classifier prediction to a RAG threat analysis.

    BENIGN is a valid prediction but not a threat -- returns (classification, None)
    rather than fabricating a threat report for traffic that wasn't classified as
    malicious.
    """
    classification = ClassificationResult(
        prediction=request.prediction,
        probability=request.probability,
        model="random_forest",
        classification="malicious" if request.prediction == "DDoS" else "benign",
    )

    if request.prediction == "BENIGN":
        return classification, None

    query = PREDICTION_TO_QUERY.get(request.prediction)
    if query is None:
        raise UnsupportedPredictionError(
            f"No threat-intelligence mapping exists for prediction {request.prediction!r}"
        )

    analysis = analyze_query(query)
    return classification, analysis
