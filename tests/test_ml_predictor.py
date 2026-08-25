import json

from backend.ml.config import FEATURE_COLUMNS, LABEL_MAP, METADATA_PATH
from backend.ml.predictor import feature_importance, model_available, predict
from backend.ml.predictor import model_version as get_model_version
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


# --- Phase 10: class_probabilities / model_version ------------------------------


def test_class_probabilities_contains_every_configured_label():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    assert result.class_probabilities is not None
    assert set(result.class_probabilities.keys()) == set(LABEL_MAP.keys())


def test_class_probabilities_are_valid_probabilities_summing_to_one():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    values = list(result.class_probabilities.values())
    assert all(0.0 <= value <= 1.0 for value in values)
    assert abs(sum(values) - 1.0) < 1e-6


def test_winning_prediction_matches_highest_class_probability():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    winner = max(result.class_probabilities, key=result.class_probabilities.get)
    assert winner == result.prediction


def test_probability_field_matches_its_own_class_probabilities_entry():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    assert result.probability == result.class_probabilities[result.prediction]


def test_model_version_is_populated_and_matches_the_standalone_helper():
    features = NetworkTrafficFeatures.model_validate(SAMPLE_PAYLOAD)
    result = predict(features)
    assert result.model_version is not None
    assert result.model_version == get_model_version()


def test_model_version_is_the_real_metadata_trained_at_value_not_fabricated():
    metadata = json.loads(METADATA_PATH.read_text())
    assert get_model_version() == metadata["trained_at"]
