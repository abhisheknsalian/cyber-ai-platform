"""Phase 17: tests for backend/evaluation/statistics.py."""

from __future__ import annotations

import pytest

from backend.evaluation.statistics import MIN_N_FOR_INFERENCE, bootstrap_mean_ci, wilson_score_interval


def test_wilson_score_interval_contains_point_estimate():
    ci = wilson_score_interval(95, 100)
    assert ci.point_estimate == 0.95
    assert ci.lower <= ci.point_estimate <= ci.upper
    assert ci.method == "wilson_score"
    assert ci.confidence_level == 0.95


def test_wilson_score_interval_narrows_with_larger_n():
    narrow = wilson_score_interval(9999, 10000)
    wide = wilson_score_interval(9, 10)
    assert (narrow.upper - narrow.lower) < (wide.upper - wide.lower)


def test_wilson_score_interval_stays_within_zero_one():
    ci = wilson_score_interval(100, 100)
    assert 0.0 <= ci.lower <= ci.upper <= 1.0


def test_wilson_score_interval_rejects_non_positive_n():
    with pytest.raises(ValueError):
        wilson_score_interval(0, 0)


def test_bootstrap_mean_ci_is_deterministic_for_a_fixed_seed():
    values = [0.9, 0.95, 1.0, 0.85, 0.92]
    a = bootstrap_mean_ci(values, seed=42, n_resamples=200)
    b = bootstrap_mean_ci(values, seed=42, n_resamples=200)
    assert a.lower == b.lower
    assert a.upper == b.upper


def test_bootstrap_mean_ci_point_estimate_is_the_sample_mean():
    values = [1.0, 2.0, 3.0, 4.0, 5.0]
    ci = bootstrap_mean_ci(values, seed=1, n_resamples=500)
    assert ci.point_estimate == pytest.approx(3.0)
    assert ci.method == "bootstrap_percentile"
    assert ci.n_resamples == 500


def test_bootstrap_mean_ci_interval_contains_the_mean_for_constant_values():
    ci = bootstrap_mean_ci([0.5] * 20, seed=1, n_resamples=200)
    assert ci.lower == pytest.approx(0.5)
    assert ci.upper == pytest.approx(0.5)


def test_bootstrap_mean_ci_rejects_empty_values():
    with pytest.raises(ValueError):
        bootstrap_mean_ci([])


def test_min_n_for_inference_is_a_positive_constant():
    assert MIN_N_FOR_INFERENCE > 0
