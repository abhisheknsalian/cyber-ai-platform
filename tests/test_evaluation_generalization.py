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


# ---------------------------------------------------------------------------
# Phase 18 (P0.1): multi-granularity near-duplicate-controlled sweep.
# ---------------------------------------------------------------------------


def test_sweep_produces_exactly_the_three_requested_granularities():
    report = run_generalization_experiment()
    sweep = report.near_duplicate_controlled_sweep
    assert sweep is not None
    assert [row.significant_digits for row in sweep] == [2, 3, 4]
    assert [row.split_name for row in sweep] == [
        "near_duplicate_controlled_2sf",
        "near_duplicate_controlled_3sf",
        "near_duplicate_controlled_4sf",
    ]


def test_sweep_entries_all_have_valid_wilson_confidence_intervals():
    report = run_generalization_experiment()
    for row in report.near_duplicate_controlled_sweep:
        assert row.accuracy_ci is not None
        assert row.accuracy_ci.method == "wilson_score"
        assert row.accuracy_ci.lower <= row.accuracy <= row.accuracy_ci.upper
        assert 0.0 <= row.accuracy_ci.lower <= row.accuracy_ci.upper <= 1.0


def test_sweep_entries_are_research_only_and_report_constrained_fraction():
    report = run_generalization_experiment()
    for row in report.near_duplicate_controlled_sweep:
        assert row.is_production_artifact is False
        assert row.fraction_rows_in_multi_row_family is not None
        assert 0.0 <= row.fraction_rows_in_multi_row_family <= 1.0
        assert row.train_rows + row.test_rows > 0


def test_sweep_3sf_entry_matches_the_backward_compatible_family_grouped_field():
    """The existing `family_grouped` field (Phase 17) and the sweep's 3sf entry
    (Phase 18) must be identical -- both are the same deterministic computation,
    reused rather than recomputed (see _near_duplicate_controlled_sweep())."""
    report = run_generalization_experiment()
    sweep_3sf = next(row for row in report.near_duplicate_controlled_sweep if row.significant_digits == 3)
    assert sweep_3sf.accuracy == report.family_grouped.accuracy
    assert sweep_3sf.test_rows == report.family_grouped.test_rows
    assert sweep_3sf.train_rows == report.family_grouped.train_rows


def test_sweep_is_deterministic_across_repeated_runs():
    first = run_generalization_experiment()
    second = run_generalization_experiment()
    for row_a, row_b in zip(first.near_duplicate_controlled_sweep, second.near_duplicate_controlled_sweep):
        assert row_a.accuracy == row_b.accuracy
        assert row_a.train_rows == row_b.train_rows
        assert row_a.test_rows == row_b.test_rows


def test_family_grouping_uses_feature_columns_not_labels():
    """Family identity must be reconstructible from FEATURE_COLUMNS alone -- the
    label is only ever used afterward, for majority-label stratification of
    already-fixed families (see _near_duplicate_controlled_result())."""
    import inspect

    from backend.evaluation import generalization_experiment as module

    source = inspect.getsource(module._family_ids)
    assert "TARGET_COLUMN" not in source
    assert "FEATURE_COLUMNS" in source


def test_sweep_never_touches_the_production_model_path():
    from backend.ml.config import MODEL_PATH

    before = MODEL_PATH.read_bytes() if MODEL_PATH.exists() else None
    run_generalization_experiment()
    after = MODEL_PATH.read_bytes() if MODEL_PATH.exists() else None
    assert before == after


def test_dose_response_note_contains_no_causal_language():
    from backend.evaluation.generalization_experiment import _FORBIDDEN_CAUSAL_PHRASES

    report = run_generalization_experiment()
    note = report.dose_response_note.lower()
    assert note  # non-empty
    for phrase in _FORBIDDEN_CAUSAL_PHRASES:
        assert phrase not in note, f"dose_response_note must never contain {phrase!r}"


def test_dose_response_note_explicitly_names_its_own_limitations():
    report = run_generalization_experiment()
    note = report.dose_response_note.lower()
    assert "observational" in note
    assert "not a verified session" in note or "proxy" in note
    assert "no formal trend" in note or "significance test" in note
    assert "production model artifact" in note


def test_limitations_document_the_sweep_scope():
    report = run_generalization_experiment()
    joined = " ".join(report.limitations).lower()
    assert "near_duplicate_controlled_sweep" in joined
    assert "attributable to" in joined
