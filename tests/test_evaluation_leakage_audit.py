"""Phase 17: tests for backend/evaluation/leakage_audit.py.

Runs against tests/conftest.py's small synthetic dataset (RAW_DATA_PATH is
env-overridden session-wide) -- fast, and its known properties (10 injected exact
duplicates, no Timestamp/Source IP/Flow ID column, random-noise features) let us
assert specific, meaningful behavior rather than just "it runs".
"""

from __future__ import annotations

import numpy as np
import pandas as pd
import pytest

from backend.evaluation.leakage_audit import (
    LeakageAuditUnavailableError,
    cross_label_collision_audit,
    family_grouping_audit,
    round_significant,
    run_leakage_audit,
    split_feasibility_audit,
)
from backend.ml.config import FEATURE_COLUMNS, RAW_DATA_PATH, TARGET_COLUMN


def test_round_significant_collapses_close_values_to_the_same_bucket():
    values = np.array([123.4, 123.6, 999.0])
    rounded = round_significant(values, 2)
    assert rounded[0] == rounded[1] == 120.0
    assert rounded[2] == 1000.0  # 999 rounds up to 3 sig figs -> 1.0e3


def test_round_significant_handles_zero():
    rounded = round_significant(np.array([0.0, 5.0]), 3)
    assert rounded[0] == 0.0


def test_split_feasibility_reports_temporal_and_host_splits_not_possible():
    report = split_feasibility_audit(RAW_DATA_PATH)
    assert report.temporal_split_possible is False
    assert report.host_split_possible is False
    assert report.family_grouped_split_possible is True
    assert "Timestamp" in report.reason


def test_cross_label_collision_audit_runs_on_a_constructed_frame():
    # Two rows with identical FEATURE_COLUMNS values but different labels --
    # exactly the case this audit exists to catch.
    row = {col: 1.0 for col in FEATURE_COLUMNS}
    df = pd.DataFrame([{**row, TARGET_COLUMN: 0}, {**row, TARGET_COLUMN: 1}])
    result = cross_label_collision_audit(df)
    assert result.affected_rows == 2
    assert result.colliding_feature_vector_groups == 1
    assert result.affected_row_rate == 1.0


def test_cross_label_collision_audit_finds_nothing_when_all_rows_distinct():
    rng = np.random.default_rng(0)
    df = pd.DataFrame({col: rng.exponential(size=20) for col in FEATURE_COLUMNS})
    df[TARGET_COLUMN] = 0
    result = cross_label_collision_audit(df)
    assert result.affected_rows == 0
    assert result.colliding_feature_vector_groups == 0


def test_family_grouping_audit_groups_identical_rounded_rows():
    row = {col: 123.456 for col in FEATURE_COLUMNS}
    slightly_different = {col: 123.460 for col in FEATURE_COLUMNS}  # same at 3 sig figs
    distinct = {col: 999.0 for col in FEATURE_COLUMNS}
    df = pd.DataFrame([row, slightly_different, distinct])
    result = family_grouping_audit(df, significant_digits=3)
    assert result.total_rows == 3
    assert result.family_count == 2
    assert result.largest_family_size == 2
    assert result.rows_in_multi_row_families == 2


def test_run_leakage_audit_end_to_end_against_synthetic_dataset():
    report = run_leakage_audit()
    # conftest.py injects exactly 10 duplicate rows into the synthetic dataset.
    assert report.exact_duplicates.duplicate_rows_before_cleaning == 10
    assert report.exact_duplicates.duplicates_removed_before_split is True
    assert report.near_duplicates.train_rows > 0
    assert report.near_duplicates.distance.count > 0
    assert report.family_grouping.total_rows > 0
    assert report.split_feasibility.temporal_split_possible is False
    assert "no grouping metadata" in report.methodology_note.lower() or "not invented" in report.methodology_note.lower()


def test_run_leakage_audit_raises_when_dataset_missing(tmp_path):
    with pytest.raises(LeakageAuditUnavailableError):
        run_leakage_audit(tmp_path / "does_not_exist.csv")
