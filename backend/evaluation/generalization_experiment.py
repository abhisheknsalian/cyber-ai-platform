"""RQ1 generalization experiment: baseline vs. a stronger, family-grouped split
(Phase 17), extended in Phase 18 (P0.1) into a multi-granularity sweep.

Trains RESEARCH-ONLY RandomForestClassifier instances in-memory for every
grouped/repeated-random-split condition -- never saves over, reads from, or
otherwise touches models/ddos_random_forest.joblib (the production artifact), which
is only ever written by backend/ml/train.py. Same architecture/hyperparameters as
production (n_estimators, same preprocessing) so every comparison isolates the
effect of the SPLIT, not a different model family.

Conditions:
1. baseline -- the actual production artifact, evaluated on the reconstructed
   production random split (same as ml_evaluation.py::evaluate_held_out_test(), just
   also expressed as a SplitEvaluationResult for direct comparison in this report).
2. family_grouped -- a research-only model trained/evaluated on a split where whole
   near-duplicate "families" (see leakage_audit.py::family_grouping_audit(), a
   documented heuristic -- this dataset has no real session identifier) are kept
   together on one side of the split, never spanning both. Only ~5.2% of rows fall
   into a multi-row family at the 3-significant-figure grouping used here (measured,
   see leakage_audit.py), so this condition is a genuine but LIMITED-power control --
   documented, not overstated.
3. near_duplicate_controlled_sweep (Phase 18, P0.1) -- the SAME family-grouped
   construction repeated at 2, 3, and 4 significant figures (the exact granularities
   leakage_audit.py already measured and disclosed: ~17.6%/~5.2%/~1.1% of rows in a
   multi-row family respectively -- no new, arbitrary parameter invented). This
   turns the single Phase 17 data point into a small dose-response comparison:
   does measured accuracy change as the grouping constraint gets stronger (more
   rows forced to stay together), and by roughly how much? A full, radius-based
   nearest-neighbor connected-components grouping over the whole ~223k-row dataset
   was considered and rejected as computationally intractable (O(n^2) at 78
   dimensions); this rounding-based sweep is the strongest tractable, fully
   reproducible alternative built entirely from already-existing, already-audited
   code. See _dose_response_note() for the generated (never hand-typed),
   descriptive-only interpretation, and RQ1's write-up in docs/THESIS_EVALUATION.md
   for why this cannot answer a causal "how much accuracy is attributable to
   near-duplicate structure" question -- only the weaker, observational one above.
4. repeated_random_splits -- the same production-style random split repeated across
   multiple seeds, to show whether the reported accuracy is a one-seed artifact or a
   stable estimate. This does not address leakage; it addresses split-to-split
   variance, and is reported as a separate, distinctly-labeled result.

If a stronger split were NOT genuinely supported by the data (no grouping signal at
all), the grouped conditions would be omitted and marked NOT MEASURABLE -- they are
included here because leakage_audit.py's family grouping does find real (if
limited, and only partially power-scalable) structure.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from backend.evaluation.leakage_audit import round_significant
from backend.evaluation.schemas import (
    GeneralizationExperimentReport,
    RepeatedSplitVarianceReport,
    SplitEvaluationResult,
)
from backend.evaluation.statistics import wilson_score_interval
from backend.ml.config import (
    FEATURE_COLUMNS,
    INVERSE_LABEL_MAP,
    LABEL_MAP,
    N_ESTIMATORS,
    RANDOM_STATE,
    RAW_DATA_PATH,
    TARGET_COLUMN,
    TEST_SIZE,
)
from backend.ml.predictor import _load_model
from backend.ml.preprocessing import load_and_clean_dataset, split_features_target

_FAMILY_SIGNIFICANT_DIGITS = 3
_REPEATED_SPLIT_SEEDS = [7, 13, 42, 99, 123]


class GeneralizationExperimentUnavailableError(RuntimeError):
    """Raised when the real dataset/production model isn't available -- never
    fabricates a generalization comparison."""


def _class_indices_names() -> tuple[list[int], list[str]]:
    indices = sorted(INVERSE_LABEL_MAP)
    return indices, [INVERSE_LABEL_MAP[i] for i in indices]


def _evaluate(model, X_test: pd.DataFrame, y_test: pd.Series) -> dict:
    class_indices, class_names = _class_indices_names()
    y_pred = model.predict(X_test).astype(int)
    proba_raw = model.predict_proba(X_test) if hasattr(model, "predict_proba") else None

    roc_auc = pr_auc = None
    if proba_raw is not None and len(class_indices) == 2 and "DDoS" in LABEL_MAP:
        column_for_index = {int(c): position for position, c in enumerate(model.classes_)}
        positive_index = column_for_index[LABEL_MAP["DDoS"]]
        y_true_binary = (y_test.to_numpy() == LABEL_MAP["DDoS"]).astype(int)
        if len(set(y_true_binary)) == 2:
            y_score = proba_raw[:, positive_index]
            roc_auc = float(roc_auc_score(y_true_binary, y_score))
            pr_auc = float(average_precision_score(y_true_binary, y_score))

    accuracy = float(accuracy_score(y_test, y_pred))
    return {
        "accuracy": accuracy,
        "precision_macro": float(precision_score(y_test, y_pred, labels=class_indices, average="macro", zero_division=0)),
        "recall_macro": float(recall_score(y_test, y_pred, labels=class_indices, average="macro", zero_division=0)),
        "f1_macro": float(f1_score(y_test, y_pred, labels=class_indices, average="macro", zero_division=0)),
        "roc_auc": roc_auc,
        "pr_auc": pr_auc,
        "confusion_matrix": confusion_matrix(y_test, y_pred, labels=class_indices).tolist(),
        "confusion_matrix_labels": class_names,
        "class_distribution": {class_names[i]: int((y_test.to_numpy() == class_indices[i]).sum()) for i in range(len(class_names))},
    }


def _split_result(
    name: str,
    description: str,
    X_train,
    X_test,
    y_train,
    y_test,
    model,
    *,
    is_production: bool,
    significant_digits: int | None = None,
    fraction_rows_in_multi_row_family: float | None = None,
) -> SplitEvaluationResult:
    metrics = _evaluate(model, X_test, y_test)
    ci = wilson_score_interval(round(metrics["accuracy"] * len(y_test)), len(y_test)) if len(y_test) > 0 else None
    return SplitEvaluationResult(
        split_name=name,
        split_description=description,
        train_rows=len(X_train),
        test_rows=len(X_test),
        is_production_artifact=is_production,
        accuracy_ci=ci,
        significant_digits=significant_digits,
        fraction_rows_in_multi_row_family=fraction_rows_in_multi_row_family,
        **metrics,
    )


def _baseline_result(df: pd.DataFrame) -> SplitEvaluationResult:
    model = _load_model()
    X, y = split_features_target(df)
    X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)
    return _split_result(
        "production_random_split",
        "The actual shipped production artifact (models/ddos_random_forest.joblib), "
        "evaluated on the reconstructed random train/test split it was originally "
        "trained/evaluated on (random_state=42, stratified, row-level).",
        X_train, X_test, y_train, y_test, model, is_production=True,
    )


def _family_ids(df: pd.DataFrame, *, significant_digits: int) -> pd.Series:
    rounded = round_significant(df[FEATURE_COLUMNS].to_numpy(dtype=float), significant_digits)
    rounded_df = pd.DataFrame(rounded, columns=FEATURE_COLUMNS, index=df.index)
    return rounded_df.groupby(list(FEATURE_COLUMNS)).ngroup()


def _fraction_rows_in_multi_row_family(family_id: pd.Series) -> float:
    sizes = family_id.value_counts()
    multi = sizes[sizes > 1]
    return round(float(multi.sum()) / len(family_id), 6) if len(family_id) else 0.0


def _near_duplicate_controlled_result(df: pd.DataFrame, *, significant_digits: int) -> SplitEvaluationResult:
    """RESEARCH-ONLY model, never saved as/over the production artifact, trained on a
    split where whole rounding-based 'families' (leakage_audit.py's heuristic
    near-duplicate grouping, at the given significant-figure precision) are kept
    entirely on one side -- no family spans both train and test. Reuses the exact
    family-construction/majority-label-stratification approach the original (Phase
    17) family_grouped condition used, parameterized over significant_digits so the
    same logic produces every point in the Phase 18 (P0.1) sweep -- see
    run_generalization_experiment()."""
    family_id = _family_ids(df, significant_digits=significant_digits)
    fraction_multi = _fraction_rows_in_multi_row_family(family_id)
    unique_families = family_id.drop_duplicates()
    # Stratify the family-level split by each family's majority label so class
    # balance is preserved at the split level, matching the production split's own
    # use of stratify=y. Label is used ONLY here, for stratification after family
    # identity is already fixed -- never to define family membership itself (that
    # comes from FEATURE_COLUMNS alone, via _family_ids()/round_significant()).
    family_majority_label = df.groupby(family_id)[TARGET_COLUMN].agg(lambda s: s.value_counts().idxmax())
    train_families, test_families = train_test_split(
        unique_families, test_size=TEST_SIZE, random_state=RANDOM_STATE,
        stratify=family_majority_label.reindex(unique_families).to_numpy(),
    )
    train_mask = family_id.isin(set(train_families))
    X, y = split_features_target(df)
    X_train, y_train = X[train_mask], y[train_mask]
    X_test, y_test = X[~train_mask], y[~train_mask]

    model = RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)
    return _split_result(
        f"near_duplicate_controlled_{significant_digits}sf",
        (
            "RESEARCH-ONLY model (never saved as/over the production artifact), same "
            "hyperparameters as production, trained/evaluated on a split where whole "
            f"rounding-based 'families' at {significant_digits} significant figures "
            "(leakage_audit.py's heuristic near-duplicate grouping -- FEATURE_COLUMNS "
            "only, label never used to define family identity) are kept entirely on "
            f"one side -- no family spans both train and test. {fraction_multi:.2%} of "
            "rows belong to a multi-row family at this grouping (see leakage_audit.py), "
            "so this condition's power to constrain near-duplicate structure scales "
            "with that fraction, not with the split's overall row count. Rounding-"
            "coordinate equality is a proxy for similarity, not a verified session/flow "
            "identity -- this is an observational comparison, not a causal experiment."
        ),
        X_train, X_test, y_train, y_test, model, is_production=False,
        significant_digits=significant_digits,
        fraction_rows_in_multi_row_family=fraction_multi,
    )


def _family_grouped_result(df: pd.DataFrame) -> SplitEvaluationResult:
    """Backward-compatible entry point: the original Phase 17 3-significant-figure
    condition, now a thin wrapper around _near_duplicate_controlled_result() so its
    logic can never drift from the Phase 18 (P0.1) sweep's 3sf point -- both are the
    identical computation, kept as separate report fields (`family_grouped` and one
    entry of `near_duplicate_controlled_sweep`) only so existing consumers of
    `family_grouped` remain unaffected."""
    return _near_duplicate_controlled_result(df, significant_digits=_FAMILY_SIGNIFICANT_DIGITS)


def _repeated_random_splits(df: pd.DataFrame, *, seeds: list[int]) -> RepeatedSplitVarianceReport:
    X, y = split_features_target(df)
    accuracies: list[float] = []
    f1_macros: list[float] = []
    for seed in seeds:
        X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=seed, stratify=y)
        model = RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=seed)
        model.fit(X_train, y_train)
        result = _evaluate(model, X_test, y_test)
        accuracies.append(result["accuracy"])
        f1_macros.append(result["f1_macro"])

    return RepeatedSplitVarianceReport(
        seeds=seeds,
        per_seed_accuracy=[round(a, 6) for a in accuracies],
        accuracy_mean=round(float(np.mean(accuracies)), 6),
        accuracy_stddev=round(float(np.std(accuracies, ddof=0)), 6),
        per_seed_f1_macro=[round(f, 6) for f in f1_macros],
        f1_macro_mean=round(float(np.mean(f1_macros)), 6),
        f1_macro_stddev=round(float(np.std(f1_macros, ddof=0)), 6),
        note=(
            f"{len(seeds)} independently-seeded RESEARCH-ONLY RandomForest models "
            "(same hyperparameters as production), each on its own random "
            "stratified row-level split of the same cleaned data -- measures "
            "split-to-split variance of the random-split methodology itself, not "
            "leakage. A small stddev shows the reported accuracy isn't a one-seed "
            "artifact; it does NOT show the split is leakage-free (see "
            "leakage_audit.py's near-duplicate findings for that question)."
        ),
    )


# Phase 18 (P0.1): the three significant-figure precisions leakage_audit.py's own
# module comment already measured and disclosed (2sf: ~17.6% of rows in a multi-row
# family, 3sf: ~5.2%, 4sf: ~1.1%) -- not new, arbitrary parameters invented for this
# sweep. 3 significant figures is the original Phase 17 family_grouped condition,
# included here too so the sweep is self-contained and directly comparable.
_SWEEP_SIGNIFICANT_DIGITS = [2, 3, 4]

# Phrases this module's generated dose_response_note must never contain -- guards
# against accidentally overstating an observational/descriptive comparison as a
# causal claim. Enforced by a unit test (tests/test_evaluation_generalization.py),
# not just this comment.
_FORBIDDEN_CAUSAL_PHRASES = (
    "proves", "prove", "causes", "cause of", "caused by", "demonstrates that",
    "accounts for", "leakage accounts for", "due to duplicates",
)


def _near_duplicate_controlled_sweep(
    df: pd.DataFrame, *, family_grouped_3sf: SplitEvaluationResult
) -> list[SplitEvaluationResult]:
    """One SplitEvaluationResult per _SWEEP_SIGNIFICANT_DIGITS value. Reuses the
    already-computed 3sf result (family_grouped_3sf) instead of retraining an
    identical model a second time -- same deterministic computation either way, so
    this is purely avoiding wasted work, not a different value."""
    results = []
    for significant_digits in _SWEEP_SIGNIFICANT_DIGITS:
        if significant_digits == _FAMILY_SIGNIFICANT_DIGITS:
            results.append(family_grouped_3sf)
        else:
            results.append(_near_duplicate_controlled_result(df, significant_digits=significant_digits))
    return results


def _dose_response_note(baseline: SplitEvaluationResult, sweep: list[SplitEvaluationResult]) -> str:
    """Generates a DESCRIPTIVE-ONLY interpretation of the sweep -- never causal
    language (see _FORBIDDEN_CAUSAL_PHRASES). Answers only: does measured accuracy
    change as progressively larger (but still minority) fractions of coordinate-
    similar row families are constrained to stay on one side of the split, and by
    roughly how much -- not why, and not what fraction of accuracy is "explained by"
    anything."""
    ordered = sorted(sweep, key=lambda r: r.significant_digits)  # 2sf (strongest constraint) ... 4sf (weakest)
    strongest, weakest = ordered[0], ordered[-1]

    per_point = "; ".join(
        f"{r.significant_digits}sf ({r.fraction_rows_in_multi_row_family:.2%} of rows in a multi-row family): "
        f"accuracy={r.accuracy:.6f} (95% CI [{r.accuracy_ci.lower:.6f}, {r.accuracy_ci.upper:.6f}])"
        for r in ordered
    )

    delta = strongest.accuracy - weakest.accuracy
    if abs(delta) < 1e-6:
        direction = (
            "Measured accuracy is effectively unchanged between the strongest "
            f"({strongest.significant_digits}sf) and weakest ({weakest.significant_digits}sf) "
            "tested grouping constraints"
        )
    elif delta < 0:
        direction = (
            f"Measured accuracy is lower under the strongest tested grouping constraint "
            f"({strongest.significant_digits}sf, {strongest.fraction_rows_in_multi_row_family:.2%} of rows "
            f"constrained) than under the weakest ({weakest.significant_digits}sf), by "
            f"{abs(delta):.6f}"
        )
    else:
        direction = (
            f"Measured accuracy is higher under the strongest tested grouping constraint "
            f"({strongest.significant_digits}sf) than under the weakest ({weakest.significant_digits}sf), by "
            f"{abs(delta):.6f}"
        )

    ci_overlap = not (strongest.accuracy_ci.upper < weakest.accuracy_ci.lower or weakest.accuracy_ci.upper < strongest.accuracy_ci.lower)
    overlap_text = (
        "the 95% confidence intervals of the strongest and weakest conditions overlap"
        if ci_overlap
        else "the 95% confidence intervals of the strongest and weakest conditions do NOT overlap"
    )

    return (
        f"Baseline (production random split) accuracy is {baseline.accuracy:.6f}. Across the swept "
        f"grouping strengths -- {per_point} -- {direction}, and {overlap_text}. This describes "
        "whether measured accuracy changes as progressively larger (but still minority) fractions of "
        "coordinate-similar row families are constrained to remain entirely on one side of the split; "
        "it does not identify a cause. Rounding-coordinate equality is only a proxy for row similarity, "
        "not a verified session/flow identity, so this is an observational comparison across split "
        "conditions, not a controlled intervention. Even the strongest swept condition "
        f"({strongest.fraction_rows_in_multi_row_family:.2%} of rows) leaves the majority of rows "
        "unconstrained -- already-singleton 'families' with nothing to group -- so this sweep cannot "
        "rule out near-duplicate structure among that unconstrained majority (see "
        "leakage_audit.py's near-duplicate nearest-neighbor-distance finding for that separate, "
        "stronger descriptive signal). With only three sweep points, no formal trend or significance "
        "test is appropriate here; the comparison above is reported descriptively only. The production "
        "model artifact (models/ddos_random_forest.joblib) was not read, modified, or retrained by "
        "this experiment -- every model referenced here is a separate, in-memory, research-only fit."
    )


def run_generalization_experiment(data_path=RAW_DATA_PATH) -> GeneralizationExperimentReport:
    if not data_path.exists():
        raise GeneralizationExperimentUnavailableError(f"Dataset not found at {data_path}.")

    df = load_and_clean_dataset(data_path)

    baseline = _baseline_result(df)
    family_grouped = _family_grouped_result(df)
    repeated = _repeated_random_splits(df, seeds=_REPEATED_SPLIT_SEEDS)
    sweep = _near_duplicate_controlled_sweep(df, family_grouped_3sf=family_grouped)
    dose_response_note = _dose_response_note(baseline, sweep)

    return GeneralizationExperimentReport(
        baseline=baseline,
        family_grouped=family_grouped,
        repeated_random_splits=repeated,
        near_duplicate_controlled_sweep=sweep,
        dose_response_note=dose_response_note,
        methodology_note=(
            "baseline reproduces the actual shipped production artifact's "
            "evaluation exactly. family_grouped is a research-only retrain (never "
            "written to the production model path) on a split built from "
            "leakage_audit.py's rounding-based near-duplicate family grouping -- a "
            "genuine but limited-power stronger control, since this CSV variant has "
            "no real session/flow identifier to group by (see "
            "leakage_audit.py::split_feasibility_audit()). repeated_random_splits "
            "measures a different, complementary question (seed-to-seed variance of "
            "the random-split methodology), not leakage-robustness."
        ),
        limitations=[
            "No temporal, host-level, or file-level split could be reconstructed: "
            "this CSV variant carries no Timestamp/Source IP/Destination IP/Flow ID "
            "column, and there is only one raw capture file. These splits are NOT "
            "MEASURABLE from the available data, not merely skipped.",
            "The family-grouped split's statistical power is limited by how much "
            "grouping the heuristic actually finds, NOT by the number of groups: "
            "there are roughly 216,000 distinct families at 3 significant figures "
            "(plenty for a group-level split in principle), but only ~5.2% of rows "
            "belong to a multi-row family -- the other ~94.8% are already singleton "
            "'families' with nothing to group. This condition therefore mostly "
            "re-tests the same effectively-random row assignment as the baseline "
            "split for the vast majority of rows; only the ~5.2% minority ever "
            "actually gets constrained to stay together.",
            "The grouping heuristic could itself introduce a mild artifact: rows in "
            "a large family (up to 53 members at this precision, see "
            "leakage_audit.py's family_grouping audit) are assigned to train or test "
            "AS A WHOLE BLOCK, so whichever side a large family lands on loses or "
            "gains many rows of one particular repeated pattern at once, slightly "
            "shifting the effective within-class pattern diversity of that split "
            "relative to a pure per-row random assignment. This is a real, if minor, "
            "side effect of grouping by feature similarity rather than a session ID.",
            "A near-zero difference between baseline and family_grouped accuracy "
            "would NOT prove the model generalizes well in general -- it would only "
            "show this particular (weak) grouping heuristic doesn't change the "
            "result. See leakage_audit.py's near-duplicate nearest-neighbor-distance "
            "finding for the stronger, independent leakage signal.",
            "Phase 18 (P0.1): near_duplicate_controlled_sweep repeats the "
            "family-grouped comparison at 2, 3, and 4 significant figures (~17.6%, "
            "~5.2%, ~1.1% of rows constrained respectively -- see "
            "leakage_audit.py) to characterize whether accuracy changes as grouping "
            "strength increases, i.e. a dose-response comparison rather than a "
            "single data point. This remains an OBSERVATIONAL comparison, not a "
            "causal experiment -- see dose_response_note, which is generated "
            "text, never hand-typed, and is checked (by "
            "tests/test_evaluation_generalization.py) to never claim accuracy is "
            "'caused by' or 'proven' by near-duplicate structure. Even the "
            "strongest tested condition (2 significant figures) still leaves the "
            "majority of rows unconstrained, so this sweep cannot answer 'how much "
            "of the apparent classification performance is attributable to "
            "near-duplicate structure' -- only whether/how much measured accuracy "
            "moves as the (still partial) grouping constraint strengthens.",
        ],
    )
