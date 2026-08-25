"""Phase 11: tests for backend/evaluation/ml_evaluation.py.

conftest.py's autouse fixtures point backend.ml.config.RAW_DATA_PATH/MODEL_PATH at a
small synthetic (but real CICFlowMeter-column-shaped) dataset and a model actually
trained on it -- these functions therefore run against real artifacts here, just not
the real ~225k-row CICIDS2017 file. Assertions are property-based (shapes, ranges,
internal consistency) rather than exact accuracy numbers, since the synthetic
dataset's accuracy is meaningless (see conftest.py's own docstring).
"""

import numpy as np
import pytest

from backend.evaluation.ml_evaluation import (
    DatasetUnavailableError,
    _load_model,
    _score,
    calibration_report,
    evaluate_full_dataset,
    evaluate_held_out_test,
    load_dataset_summary,
    load_model_summary,
    threshold_analysis,
)
from backend.ml.config import FEATURE_COLUMNS, LABEL_MAP
from backend.ml.preprocessing import load_and_clean_dataset, split_features_target


def test_load_dataset_summary_class_distribution_sums_to_rows_after_cleaning():
    summary = load_dataset_summary()
    assert sum(summary.class_distribution.values()) == summary.rows_after_cleaning
    assert summary.rows_after_cleaning <= summary.total_rows_before_cleaning
    assert summary.class_labels == sorted(summary.class_distribution)
    assert set(summary.class_labels) <= set(LABEL_MAP)


def test_load_dataset_summary_raises_on_missing_dataset(tmp_path):
    with pytest.raises(DatasetUnavailableError):
        load_dataset_summary(tmp_path / "does_not_exist.csv")


def test_load_model_summary_matches_trained_feature_and_class_configuration():
    summary = load_model_summary()
    assert summary.feature_count == len(FEATURE_COLUMNS)
    assert set(summary.trained_class_labels) <= set(LABEL_MAP)
    assert summary.model_version is not None


def test_held_out_test_metrics_are_a_true_held_out_split_disjoint_from_the_model():
    metrics, cross_check = evaluate_held_out_test()

    assert metrics.split == "held_out_test"
    assert 0.0 <= metrics.accuracy <= 1.0
    assert 0.0 <= metrics.balanced_accuracy <= 1.0
    assert metrics.samples == cross_check["reconstructed_test_rows"]
    assert metrics.samples > 0


def test_held_out_test_confusion_matrix_dimensions_match_class_count():
    metrics, _ = evaluate_held_out_test()
    n_classes = len(metrics.confusion_matrix_labels)

    assert len(metrics.confusion_matrix) == n_classes
    assert all(len(row) == n_classes for row in metrics.confusion_matrix)
    assert set(metrics.per_class.keys()) == set(metrics.confusion_matrix_labels)
    assert sum(row_sum for row in metrics.confusion_matrix for row_sum in row) == metrics.samples


def test_held_out_test_per_class_support_sums_to_total_samples():
    metrics, _ = evaluate_held_out_test()
    assert sum(pc.support for pc in metrics.per_class.values()) == metrics.samples


def test_held_out_test_inference_latency_sample_is_bounded_and_positive():
    metrics, _ = evaluate_held_out_test()
    latency = metrics.inference_latency_ms
    assert latency.count == min(300, metrics.samples)
    assert latency.count > 0
    assert 0.0 <= latency.min_ms <= latency.mean_ms <= latency.max_ms
    assert latency.p50_ms >= 0.0


def test_full_dataset_metrics_cover_every_cleaned_row():
    from backend.ml.config import RAW_DATA_PATH

    df = load_and_clean_dataset(RAW_DATA_PATH)
    metrics = evaluate_full_dataset()

    assert metrics.split == "full_dataset"
    assert metrics.samples == len(df)


def test_full_dataset_metrics_respect_max_samples_truncation():
    metrics = evaluate_full_dataset(max_samples=10)
    assert metrics.samples == 10


def test_threshold_analysis_points_are_monotonically_increasing_thresholds():
    analysis = threshold_analysis()
    if analysis is None:
        pytest.skip("Not a binary BENIGN/DDoS model in this configuration")

    thresholds = [p.threshold for p in analysis.points]
    assert thresholds == sorted(thresholds)
    assert analysis.best_f1_threshold in thresholds
    assert analysis.production_threshold == 0.5


def test_threshold_analysis_point_metrics_are_valid_rates():
    analysis = threshold_analysis()
    if analysis is None:
        pytest.skip("Not a binary BENIGN/DDoS model in this configuration")

    for point in analysis.points:
        for value in (point.precision, point.recall, point.f1, point.false_positive_rate, point.false_negative_rate):
            assert 0.0 <= value <= 1.0


def test_calibration_report_brier_score_and_bin_counts_cover_the_test_set():
    report = calibration_report()
    if report is None:
        pytest.skip("Not a binary BENIGN/DDoS model in this configuration")

    assert report.brier_score >= 0.0
    assert len(report.bins) == 10
    _, cross_check = evaluate_held_out_test()
    assert sum(b.count for b in report.bins) == cross_check["reconstructed_test_rows"]

    for bin_ in report.bins:
        if bin_.count > 0:
            assert bin_.bin_lower <= bin_.mean_predicted_probability <= bin_.bin_upper + 1e-9
            assert 0.0 <= bin_.empirical_positive_rate <= 1.0


def test_scored_split_probabilities_sum_to_approximately_one():
    """White-box check on _score() (this module's own probability-column-reordering
    logic, see its docstring) -- distinct from backend/ml/predictor.py's own,
    already-tested predict_proba() correctness (tests/test_ml_predictor.py)."""
    from backend.ml.config import RAW_DATA_PATH

    model = _load_model()
    df = load_and_clean_dataset(RAW_DATA_PATH)
    X, y = split_features_target(df)
    scored = _score(model, X.head(20), y.head(20), latency_sample_size=5)

    row_sums = scored.proba.sum(axis=1)
    assert np.allclose(row_sums, 1.0, atol=1e-6)
