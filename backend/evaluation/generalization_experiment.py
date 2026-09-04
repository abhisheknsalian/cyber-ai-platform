"""RQ1 generalization experiment: baseline vs. a stronger, family-grouped split
(Phase 17).

Trains RESEARCH-ONLY RandomForestClassifier instances in-memory for the
family-grouped and repeated-random-split conditions -- never saves over, reads from,
or otherwise touches models/ddos_random_forest.joblib (the production artifact),
which is only ever written by backend/ml/train.py. Same architecture/hyperparameters
as production (n_estimators, same preprocessing) so the comparison isolates the
effect of the SPLIT, not a different model family.

Three conditions:
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
3. repeated_random_splits -- the same production-style random split repeated across
   multiple seeds, to show whether the reported accuracy is a one-seed artifact or a
   stable estimate. This does not address leakage; it addresses split-to-split
   variance, and is reported as a separate, distinctly-labeled result.

If a stronger split were NOT genuinely supported by the data (no grouping signal at
all), condition 2 would be omitted and marked NOT MEASURABLE -- it is included here
because leakage_audit.py's family grouping does find real (if limited) structure.
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


def _split_result(name: str, description: str, X_train, X_test, y_train, y_test, model, *, is_production: bool) -> SplitEvaluationResult:
    metrics = _evaluate(model, X_test, y_test)
    ci = wilson_score_interval(round(metrics["accuracy"] * len(y_test)), len(y_test)) if len(y_test) > 0 else None
    return SplitEvaluationResult(
        split_name=name,
        split_description=description,
        train_rows=len(X_train),
        test_rows=len(X_test),
        is_production_artifact=is_production,
        accuracy_ci=ci,
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


def _family_grouped_result(df: pd.DataFrame) -> SplitEvaluationResult:
    family_id = _family_ids(df, significant_digits=_FAMILY_SIGNIFICANT_DIGITS)
    unique_families = family_id.drop_duplicates()
    # Stratify the family-level split by each family's majority label so class
    # balance is preserved at the split level, matching the production split's own
    # use of stratify=y.
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
        "family_grouped_split",
        "RESEARCH-ONLY model (never saved as/over the production artifact), same "
        "hyperparameters as production, trained/evaluated on a split where whole "
        "rounding-based 'families' (leakage_audit.py's heuristic near-duplicate "
        "grouping, 3 significant figures) are kept entirely on one side -- no family "
        "spans both train and test. Only ~5.2% of rows belong to a multi-row family "
        "at this grouping (see leakage_audit.py), so this is a genuine but "
        "LIMITED-power control, not a full session-level split.",
        X_train, X_test, y_train, y_test, model, is_production=False,
    )


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


def run_generalization_experiment(data_path=RAW_DATA_PATH) -> GeneralizationExperimentReport:
    if not data_path.exists():
        raise GeneralizationExperimentUnavailableError(f"Dataset not found at {data_path}.")

    df = load_and_clean_dataset(data_path)

    baseline = _baseline_result(df)
    family_grouped = _family_grouped_result(df)
    repeated = _repeated_random_splits(df, seeds=_REPEATED_SPLIT_SEEDS)

    return GeneralizationExperimentReport(
        baseline=baseline,
        family_grouped=family_grouped,
        repeated_random_splits=repeated,
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
        ],
    )
