from backend.ml.config import FEATURE_COLUMNS
from backend.ml.predictor import feature_importance, model_available, predict
from backend.ml.schemas import NetworkTrafficFeatures

SAMPLE_PAYLOAD = {column: 1000.0 for column in FEATURE_COLUMNS}


def test_model_loads():
    assert model_available() is True


def test_expected_feature_schema_is_validated():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    dumped = features.model_dump(by_alias=True)
    assert set(dumped.keys()) == set(FEATURE_COLUMNS)


def test_prediction_works():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    assert result.prediction in ("BENIGN", "DDoS")
    assert result.classification in ("benign", "malicious")
    assert result.model == "random_forest"


def test_probability_is_a_valid_class_probability():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    # RandomForestClassifier always exposes predict_proba, so this should be populated.
    assert result.probability is not None
    assert 0.0 <= result.probability <= 1.0


def test_feature_importance_returns_ranked_list():
    items = feature_importance(top_n=5)
    assert len(items) == 5
    importances = [item.importance for item in items]
    assert importances == sorted(importances, reverse=True)
    assert all(0.0 <= value <= 1.0 for value in importances)
    assert {item.feature for item in items} <= set(FEATURE_COLUMNS)
