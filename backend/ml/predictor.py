import logging
import time
from functools import lru_cache

import joblib

from backend.ml.config import FEATURE_COLUMNS, INVERSE_LABEL_MAP, MODEL_PATH
from backend.ml.preprocessing import features_dict_to_frame
from backend.ml.schemas import ClassificationResult, FeatureImportanceItem, NetworkTrafficFeatures

logger = logging.getLogger("backend.ml")


class ModelUnavailableError(RuntimeError):
    """Raised when no trained model artifact exists yet."""


def model_available() -> bool:
    return MODEL_PATH.exists()


@lru_cache(maxsize=1)
def _load_model():
    if not MODEL_PATH.exists():
        raise ModelUnavailableError(
            f"No trained model found at {MODEL_PATH}. Train one first with: "
            "uv run python -m backend.ml.train"
        )
    return joblib.load(MODEL_PATH)


def predict(features: NetworkTrafficFeatures) -> ClassificationResult:
    model = _load_model()
    frame = features_dict_to_frame(features.model_dump(by_alias=True))

    # Logs the prediction/probability/duration only -- never the input feature vector
    # itself (78 raw network-flow measurements aren't a secret, but they're also not
    # needed to understand classifier behavior operationally, so they're left out).
    start = time.perf_counter()
    label_index = int(model.predict(frame)[0])
    prediction = INVERSE_LABEL_MAP[label_index]

    probability = None
    if hasattr(model, "predict_proba"):
        probability = float(model.predict_proba(frame)[0][label_index])
    duration_ms = round((time.perf_counter() - start) * 1000, 2)

    logger.info(
        "Classifier inference completed",
        extra={
            "event": "classifier_inference",
            "prediction": prediction,
            "probability": probability,
            "duration_ms": duration_ms,
        },
    )

    return ClassificationResult(
        prediction=prediction,
        probability=probability,
        model="random_forest",
        classification="malicious" if prediction == "DDoS" else "benign",
    )


def feature_importance(top_n: int = 15) -> list[FeatureImportanceItem]:
    model = _load_model()
    if not hasattr(model, "feature_importances_"):
        raise ModelUnavailableError("Loaded model does not expose feature_importances_")

    ranked = sorted(
        zip(FEATURE_COLUMNS, model.feature_importances_),
        key=lambda pair: pair[1],
        reverse=True,
    )
    return [FeatureImportanceItem(feature=name, importance=float(value)) for name, value in ranked[:top_n]]
