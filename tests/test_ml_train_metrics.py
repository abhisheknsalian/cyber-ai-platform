"""Phase 10: tests for backend/ml/train.py's compute_classification_metrics() (a pure
function over already-known, test-only prediction arrays -- no training happens in
this file, no real dataset is touched) and backend/ml/preprocessing.py's
compute_dataset_quality_stats().

The "more than two classes" test patches INVERSE_LABEL_MAP with a temporary,
test-only dict to prove the metrics *math* is class-count-agnostic -- it does not add
a class to the real LABEL_MAP, the real dataset, or the trained model.
"""

from unittest.mock import patch

import numpy as np
import pandas as pd

from backend.ml.preprocessing import compute_dataset_quality_stats
from backend.ml.train import compute_classification_metrics


def test_binary_metrics_work_with_the_currently_configured_labels():
    y_test = np.array([0, 0, 1, 1, 1])
    y_pred = np.array([0, 1, 1, 1, 0])
    metrics, report = compute_classification_metrics(y_test, y_pred)

    assert set(metrics["per_class"].keys()) == {"BENIGN", "DDoS"}
    assert 0.0 <= metrics["accuracy"] <= 1.0
    assert "precision_macro" in metrics and "recall_macro" in metrics
    assert "f1_macro" in metrics and "f1_weighted" in metrics
    assert "BENIGN" in report and "DDoS" in report


def test_perfect_predictions_yield_perfect_metrics():
    y_test = np.array([0, 0, 1, 1])
    y_pred = np.array([0, 0, 1, 1])
    metrics, _ = compute_classification_metrics(y_test, y_pred)

    assert metrics["accuracy"] == 1.0
    assert metrics["f1_macro"] == 1.0
    assert metrics["f1_weighted"] == 1.0
    for per_class in metrics["per_class"].values():
        assert per_class["precision"] == 1.0
        assert per_class["recall"] == 1.0
        assert per_class["f1"] == 1.0


def test_confusion_matrix_and_labels_are_ordered_by_configured_label_index():
    y_test = np.array([0, 1])
    y_pred = np.array([0, 1])
    metrics, _ = compute_classification_metrics(y_test, y_pred)

    assert metrics["confusion_matrix_labels"] == ["BENIGN", "DDoS"]
    assert len(metrics["confusion_matrix"]) == 2


def test_metrics_generalize_to_more_than_two_classes_via_synthetic_test_only_arrays():
    # Test-only patch -- LABEL_MAP/the real dataset/the trained model are untouched.
    fake_inverse_label_map = {0: "BENIGN", 1: "DDoS", 2: "PortScan"}
    y_test = np.array([0, 1, 2, 2, 1, 0])
    y_pred = np.array([0, 1, 2, 1, 1, 0])

    with patch("backend.ml.train.INVERSE_LABEL_MAP", fake_inverse_label_map):
        metrics, report = compute_classification_metrics(y_test, y_pred)

    assert set(metrics["per_class"].keys()) == {"BENIGN", "DDoS", "PortScan"}
    assert metrics["confusion_matrix_labels"] == ["BENIGN", "DDoS", "PortScan"]
    assert len(metrics["confusion_matrix"]) == 3
    assert "PortScan" in report


def test_metrics_do_not_crash_on_a_class_missing_from_the_predictions():
    # zero_division=0 must be in effect -- a class present in y_test but never
    # predicted should report 0.0 precision/recall, not raise.
    fake_inverse_label_map = {0: "BENIGN", 1: "DDoS", 2: "PortScan"}
    y_test = np.array([0, 1, 2])
    y_pred = np.array([0, 1, 1])  # PortScan (2) never predicted

    with patch("backend.ml.train.INVERSE_LABEL_MAP", fake_inverse_label_map):
        metrics, _ = compute_classification_metrics(y_test, y_pred)

    assert metrics["per_class"]["PortScan"]["precision"] == 0.0
    assert metrics["per_class"]["PortScan"]["recall"] == 0.0


# --- compute_dataset_quality_stats -----------------------------------------------


def test_dataset_quality_stats_detects_duplicates_missing_and_infinite_values(tmp_path):
    csv_path = tmp_path / "synthetic_quality.csv"
    df = pd.DataFrame(
        {
            "Destination Port": [80.0, 80.0, 443.0, np.nan, np.inf],
            "Label": ["BENIGN", "BENIGN", "DDoS", "DDoS", "DDoS"],
        }
    )
    df.to_csv(csv_path, index=False)

    stats = compute_dataset_quality_stats(csv_path)

    assert stats["total_rows_before_cleaning"] == 5
    assert stats["duplicate_rows"] == 1
    assert stats["missing_value_total"] == 1
    assert stats["infinite_value_total"] == 1
    assert stats["missing_values_by_column"] == {"Destination Port": 1}
    assert stats["infinite_values_by_column"] == {"Destination Port": 1}


def test_dataset_quality_stats_on_a_clean_file_reports_zero(tmp_path):
    csv_path = tmp_path / "clean.csv"
    df = pd.DataFrame({"Destination Port": [80.0, 443.0], "Label": ["BENIGN", "DDoS"]})
    df.to_csv(csv_path, index=False)

    stats = compute_dataset_quality_stats(csv_path)

    assert stats["duplicate_rows"] == 0
    assert stats["missing_value_total"] == 0
    assert stats["infinite_value_total"] == 0
    assert stats["missing_values_by_column"] == {}
    assert stats["infinite_values_by_column"] == {}


def test_dataset_quality_stats_against_the_real_local_dataset_if_present():
    from backend.ml.config import RAW_DATA_PATH

    if not RAW_DATA_PATH.exists():
        return  # environment without the real (gitignored) dataset -- nothing to check
    stats = compute_dataset_quality_stats(RAW_DATA_PATH)
    assert stats["total_rows_before_cleaning"] > 0
    assert 0.0 <= stats["duplicate_rate"] <= 1.0
