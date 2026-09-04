"""Phase 17: tests for backend/evaluation/generalization_experiment.py.

Runs against tests/conftest.py's small synthetic dataset + trained model (both
session-scoped fixtures) -- fast enough for the normal suite since the synthetic
dataset is only ~240 rows, unlike a real ~80-second run against the full CICIDS2017
CSV.
"""

from __future__ import annotations

import pytest

from backend.evaluation.generalization_experiment import (
    GeneralizationExperimentUnavailableError,
    run_generalization_experiment,
)


def test_baseline_reflects_the_actual_production_artifact():
    report = run_generalization_experiment()
    assert report.baseline.is_production_artifact is True
    assert report.baseline.train_rows > 0
    assert report.baseline.test_rows > 0
    assert 0.0 <= report.baseline.accuracy <= 1.0
    assert report.baseline.accuracy_ci is not None
    assert report.baseline.accuracy_ci.lower <= report.baseline.accuracy <= report.baseline.accuracy_ci.upper


def test_family_grouped_split_is_research_only_and_never_production():
    report = run_generalization_experiment()
    assert report.family_grouped is not None
    assert report.family_grouped.is_production_artifact is False
    assert report.family_grouped.train_rows + report.family_grouped.test_rows > 0


def test_family_grouped_split_never_touches_the_production_model_path():
    from backend.ml.config import MODEL_PATH

    before = MODEL_PATH.read_bytes() if MODEL_PATH.exists() else None
    run_generalization_experiment()
    after = MODEL_PATH.read_bytes() if MODEL_PATH.exists() else None
    assert before == after


def test_repeated_random_splits_reports_variance_across_seeds():
    report = run_generalization_experiment()
    variance = report.repeated_random_splits
    assert len(variance.seeds) == len(variance.per_seed_accuracy) == len(variance.per_seed_f1_macro)
    assert variance.accuracy_stddev >= 0.0
    assert 0.0 <= variance.accuracy_mean <= 1.0


def test_limitations_document_unmeasurable_splits():
    report = run_generalization_experiment()
    joined = " ".join(report.limitations).lower()
    assert "temporal" in joined
    assert "not measurable" in joined
    # At least one limitation explicitly names the missing-metadata reason.
    assert any("timestamp" in item.lower() or "flow id" in item.lower() for item in report.limitations)


def test_raises_when_dataset_missing(tmp_path):
    with pytest.raises(GeneralizationExperimentUnavailableError):
        run_generalization_experiment(tmp_path / "does_not_exist.csv")


def test_report_round_trips_through_json():
    from backend.evaluation.schemas import GeneralizationExperimentReport

    report = run_generalization_experiment()
    reloaded = GeneralizationExperimentReport.model_validate(report.model_dump())
    assert reloaded.baseline.accuracy == report.baseline.accuracy
