import json
import logging
import time
from functools import lru_cache

import joblib

from backend.ml.config import FEATURE_COLUMNS, INVERSE_LABEL_MAP, METADATA_PATH, MODEL_PATH
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


@lru_cache(maxsize=1)
def _load_metadata() -> dict | None:
    """backend/ml/train.py's own metadata.json for the currently loaded model --
    read-only. Returns None (not an error) if the file is missing or unparseable, so
    a model artifact placed without its sibling metadata file still works; it just
    reports model_version=None (see model_version() below)."""
    if not METADATA_PATH.exists():
        return None
    try:
        return json.loads(METADATA_PATH.read_text())
    except (json.JSONDecodeError, OSError):
        logger.warning(
            "Model metadata file exists but could not be parsed",
            extra={"event": "metadata_unreadable", "path": str(METADATA_PATH)},
        )
        return None


def model_version() -> str | None:
    """The legitimate existing identifier for the trained artifact in use: the
    metadata file's own `trained_at` timestamp. There is no separate "version" field
    in the existing metadata format (see backend/ml/train.py) and none is invented
    here -- trained_at already uniquely identifies which training run produced the
    currently loaded model.joblib, which is exactly what this field is for."""
    metadata = _load_metadata()
    if metadata is None:
        return None
    return metadata.get("trained_at")


def _class_probabilities(model, proba_row) -> dict[str, float]:
    """Maps predict_proba()'s columns to class labels via model.classes_ (sklearn's
    own record of which label each column corresponds to, in the order it was
    fitted -- always sorted ascending) rather than assuming column position equals
    label index. For the current 2-class model this produces the exact same mapping
    the old fixed-position code did (LABEL_MAP is already {"BENIGN": 0, "DDoS": 1},
    and sklearn sorts classes_ ascending, so position 0/1 already matched); this
    generalizes correctly if a model is ever trained with more classes, or classes in
    a different label-index arrangement."""
    return {
        INVERSE_LABEL_MAP[int(class_index)]: float(p)
        for class_index, p in zip(model.classes_, proba_row)
        if int(class_index) in INVERSE_LABEL_MAP
    }


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
    class_probabilities = None
    if hasattr(model, "predict_proba"):
        proba_row = model.predict_proba(frame)[0]
        class_probabilities = _class_probabilities(model, proba_row)
        # The winning prediction's own probability, read back out of the same
        # dict that's returned as class_probabilities -- guarantees the two are
        # always consistent with each other (see tests/test_ml_predictor.py).
        probability = class_probabilities.get(prediction)
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
        # Generalizes beyond a DDoS-specific check: any non-BENIGN prediction is
        # "malicious". Behaviorally identical to the old `== "DDoS"` check for the
        # current 2-class model, but doesn't need editing if a real class is added.
        classification="malicious" if prediction != "BENIGN" else "benign",
        class_probabilities=class_probabilities,
        model_version=model_version(),
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
