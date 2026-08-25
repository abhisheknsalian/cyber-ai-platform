import math
from typing import Literal

from pydantic import BaseModel, ConfigDict, Field, create_model, field_validator

from backend.intelligence.schemas import HybridEvidence
from backend.ml.config import FEATURE_COLUMNS, LABEL_MAP
from backend.models.schemas import ThreatAnalysis


def _reject_non_finite(cls, value: float) -> float:
    if isinstance(value, bool) or not isinstance(value, (int, float)):
        raise ValueError("value must be numeric")
    if math.isnan(value) or math.isinf(value):
        raise ValueError("value must be a finite number (NaN/Infinity are not allowed)")
    return float(value)


def _check_supported_label(value: str) -> str:
    """Runtime validation against LABEL_MAP (backend/ml/config.py) -- the single
    source of truth for which classes actually exist -- instead of a hardcoded
    Literal["BENIGN", "DDoS"]. This is not weakened-to-any-string validation: an
    unsupported label is still rejected, exactly as the old Literal would reject it,
    but a genuine future class only requires adding it to LABEL_MAP (and retraining),
    not editing a Literal here too. Phase 10 does not add any label beyond the two
    LABEL_MAP already has."""
    if value not in LABEL_MAP:
        raise ValueError(
            f"Unsupported prediction label: {value!r}. Configured labels: {sorted(LABEL_MAP)}"
        )
    return value


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
    # str, not Literal["BENIGN", "DDoS"] -- validated at runtime against LABEL_MAP
    # (see _check_supported_label above) so this schema stays correct if a real class
    # is ever added via LABEL_MAP + retraining, without a second hardcoded edit here.
    prediction: str
    # Model probability for the predicted class (RandomForestClassifier.predict_proba),
    # i.e. the fraction of trees that voted for that class -- not a calibrated
    # real-world certainty. None if the loaded model has no predict_proba.
    probability: float | None = None
    model: Literal["random_forest"] = "random_forest"
    classification: Literal["malicious", "benign"]
    # Phase 10, additive: the complete predict_proba() vector keyed by class label
    # (every class the model was trained on, not just the winning one) -- e.g.
    # {"BENIGN": 0.02, "DDoS": 0.98}. None if the loaded model has no predict_proba.
    # backend/ml/predictor.py builds this from model.classes_, never fabricated.
    class_probabilities: dict[str, float] | None = None
    # Phase 10, additive: which trained artifact produced this prediction. Sourced
    # from the model metadata file's own `trained_at` timestamp (backend/ml/train.py
    # already writes this on every training run) -- there is no separate "version"
    # concept in the existing metadata format, so trained_at is reused as the
    # legitimate existing identifier rather than inventing a new one. None if no
    # metadata file is present (see backend/ml/predictor.py's model_version()).
    model_version: str | None = None

    @field_validator("prediction")
    @classmethod
    def _validate_prediction(cls, value: str) -> str:
        return _check_supported_label(value)

    @field_validator("class_probabilities")
    @classmethod
    def _validate_class_probabilities(cls, value: dict[str, float] | None) -> dict[str, float] | None:
        if value is None:
            return value
        for label in value:
            _check_supported_label(label)
        return value


class FeatureImportanceItem(BaseModel):
    feature: str
    importance: float


class ClassificationAnalysisRequest(BaseModel):
    """Input to POST /analyze/classification -- an already-computed classifier
    prediction (e.g. from POST /classify), not raw traffic features."""

    # str, not Literal -- same reasoning as ClassificationResult.prediction above.
    # This also makes backend/services/classification.py's UnsupportedPredictionError
    # path the one actually reached for an unsupported label (previously a Literal
    # would have rejected it earlier, via a generic 422 from FastAPI itself, before
    # that explicit/controlled path ever ran) -- same observable status code (422)
    # either way, so this is not a behavior change for existing clients.
    prediction: str
    probability: float | None = None

    @field_validator("prediction")
    @classmethod
    def _validate_prediction(cls, value: str) -> str:
        return _check_supported_label(value)


class ClassificationAnalysisResponse(BaseModel):
    classification: ClassificationResult
    # None when classification == "benign": there is no threat to analyze, and a
    # RAG report is never fabricated for non-malicious traffic.
    analysis: ThreatAnalysis | None = None
    # Phase 9, additive: the hybrid evidence bundle backing `analysis` -- classifier
    # prediction/probability, vector matches, and graph relationships, all backend-
    # computed. None whenever `analysis` is None (nothing to attribute). Existing
    # clients that only read `classification`/`analysis` are unaffected by this field.
    evidence: HybridEvidence | None = None
