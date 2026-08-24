import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator

from backend.ml.config import FEATURE_COLUMNS
from backend.models.schemas import ThreatAnalysis


def _reject_non_finite(cls, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("value must be numeric")
    if math.isnan(value) or math.isinf(value):
        raise ValueError("value must be a finite number (NaN/Infinity are not allowed)")
    return float(value)


# One Pydantic field per trained feature, built from the single FEATURE_COLUMNS source of
# truth (backend/ml/config.py) so the request schema can never drift from what the model
# was actually trained on. Field aliases use the exact CICFlowMeter column names (e.g.
# "Flow Bytes/s") since those aren't valid Python identifiers; `populate_by_name` also
# accepts the generated snake_case attribute names.
_FIELD_DEFINITIONS = {
    column: (float, Field(..., alias=column)) for column in FEATURE_COLUMNS
}

NetworkTrafficFeatures = create_model(
    "NetworkTrafficFeatures",
    __config__=ConfigDict(populate_by_name=True, extra="forbid"),
    __validators__={
        "_reject_non_finite": field_validator("*", mode="after")(_reject_non_finite),
    },
    **_FIELD_DEFINITIONS,
)


class ClassificationResult(BaseModel):
    prediction: Literal["BENIGN", "DDoS"]
    # Model probability for the predicted class (RandomForestClassifier.predict_proba),
    # i.e. the fraction of trees that voted for that class -- not a calibrated
    # real-world certainty. None if the loaded model has no predict_proba.
    probability: float | None = None
    model: Literal["random_forest"] = "random_forest"
    classification: Literal["malicious", "benign"]


class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float


class ClassificationAnalysisRequest(BaseModel):
    """Input to POST /analyze/classification -- an already-computed classifier
    prediction (e.g. from POST /classify), not raw traffic features."""

    prediction: Literal["BENIGN", "DDoS"]
    probability: float | None = None


class ClassificationAnalysisResponse(BaseModel):
    classification: ClassificationResult
    # None when classification == "benign": there is no threat to analyze, and a
    # RAG report is never fabricated for non-malicious traffic.
    analysis: ThreatAnalysis | None = None
