"""Statistical-interval helpers (Phase 17).

Deliberately minimal: two well-established, textbook methods, applied only where a
caller's own sample size/design justifies interval estimation (see each report's
methodology_note for that judgment). No hypothesis tests, no p-values -- the task
this module serves is "how much should this point estimate be trusted", not
"is condition A significantly different from condition B", which several Phase 17
experiments (e.g. hybrid vs. vector-only, where the two conditions share the exact
same underlying ranked list -- see hybrid_ablation.py) don't have independent samples
to support anyway.
"""

from __future__ import annotations

import math

import numpy as np

from backend.evaluation.schemas import ConfidenceInterval

# Below this many independent observations, a bootstrap/Wilson interval is reported
# as descriptive only by callers rather than omitted -- the interval itself is still
# mathematically valid at any n, but callers should widen their own interpretation
# accordingly. Kept as a named constant so "why 30" has one answer, not one per call
# site.
MIN_N_FOR_INFERENCE = 30


def wilson_score_interval(successes: int, n: int, *, confidence_level: float = 0.95) -> ConfidenceInterval:
    """Wilson score interval for a binomial proportion (e.g. classifier accuracy on a
    held-out test set: each sample is an independent correct/incorrect Bernoulli
    trial). Preferred over the naive normal-approximation interval because it stays
    within [0, 1] and remains reasonable even when the proportion is very close to 0
    or 1 -- exactly the regime this project's near-perfect accuracy figures fall in.
    """
    if n <= 0:
        raise ValueError("n must be positive")
    z = 1.959963984540054 if abs(confidence_level - 0.95) < 1e-9 else _z_for(confidence_level)
    p_hat = successes / n
    denom = 1 + z**2 / n
    center = (p_hat + z**2 / (2 * n)) / denom
    half_width = (z * math.sqrt((p_hat * (1 - p_hat) / n) + (z**2 / (4 * n**2)))) / denom
    return ConfidenceInterval(
        point_estimate=round(p_hat, 6),
        lower=round(max(0.0, center - half_width), 6),
        upper=round(min(1.0, center + half_width), 6),
        confidence_level=confidence_level,
        method="wilson_score",
    )


def _z_for(confidence_level: float) -> float:
    # Inverse-normal CDF via a rational approximation would be overkill for the two
    # confidence levels this project ever actually uses; a tiny lookup covers both,
    # and anything else falls back to the standard 95% z-score with a wider caller
    # note expected.
    return {0.90: 1.6448536269514722, 0.99: 2.5758293035489004}.get(round(confidence_level, 2), 1.959963984540054)


def bootstrap_mean_ci(
    values: list[float],
    *,
    confidence_level: float = 0.95,
    n_resamples: int = 2000,
    seed: int = 42,
) -> ConfidenceInterval:
    """Percentile bootstrap CI for the mean of a set of independent per-item
    measurements (e.g. per-query Recall@k values). Valid at any n, but reported by
    callers as descriptive-only below MIN_N_FOR_INFERENCE -- a small sample still
    produces a mathematically correct interval, just typically a very wide one, which
    is itself the honest signal ("too little data to say much"), not a defect.
    """
    if not values:
        raise ValueError("values must be non-empty")
    array = np.array(values, dtype=float)
    rng = np.random.default_rng(seed)
    n = len(array)
    resample_means = np.empty(n_resamples)
    for i in range(n_resamples):
        sample = array[rng.integers(0, n, size=n)]
        resample_means[i] = sample.mean()
    alpha = (1 - confidence_level) / 2
    lower = float(np.percentile(resample_means, 100 * alpha))
    upper = float(np.percentile(resample_means, 100 * (1 - alpha)))
    return ConfidenceInterval(
        point_estimate=round(float(array.mean()), 6),
        lower=round(lower, 6),
        upper=round(upper, 6),
        confidence_level=confidence_level,
        method="bootstrap_percentile",
        n_resamples=n_resamples,
    )
