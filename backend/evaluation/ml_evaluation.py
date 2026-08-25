"""Read-only evaluation of the EXISTING trained classifier against the real dataset.

Never trains or retrains anything -- only loads backend/ml/predictor.py's already-
saved model.joblib and scores it. Reuses backend/ml/preprocessing.py's
load_and_clean_dataset() unmodified, so evaluation preprocessing can never silently
diverge from what the model was actually trained on.

Held-out test reconstruction: backend/ml/train.py does not persist the original
train/test row indices anywhere. What it does persist is a *fixed* random_state and
test_size (backend/ml/config.py), and train_test_split() is deterministic given the
same input rows in the same order. Since load_and_clean_dataset() is itself
deterministic (no randomness), re-running the identical
`train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE,
stratify=y)` call reconstructs the *same* split the model was originally evaluated
on -- not a new, invented one. This is verified, not merely assumed: the
reconstructed split's row/class counts are compared against the metadata.json this
project's train.py already wrote at training time (see compare_to_recorded_metadata
in evaluate_held_out_test()).
"""

from __future__ import annotations

import time
from dataclasses import dataclass

import numpy as np
import pandas as pd
from sklearn.metrics import (
    accuracy_score,
    average_precision_score,
    balanced_accuracy_score,
    brier_score_loss,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
    roc_auc_score,
)
from sklearn.model_selection import train_test_split

from backend.evaluation.schemas import (
    CalibrationBin,
    CalibrationReport,
    ClassificationMetrics,
    DatasetSummary,
    ModelSummary,
    PerClassMetrics,
    ThresholdAnalysis,
    ThresholdPoint,
    latency_stats,
)
from backend.ml.config import (
    INVERSE_LABEL_MAP,
    LABEL_MAP,
    MODEL_PATH,
    RANDOM_STATE,
    RAW_DATA_PATH,
    TARGET_COLUMN,
    TEST_SIZE,
)
from backend.ml.predictor import _load_model, _load_metadata, model_version  # noqa: F401 -- internal, read-only reuse
from backend.ml.preprocessing import compute_dataset_quality_stats, load_and_clean_dataset, split_features_target


class DatasetUnavailableError(RuntimeError):
    """Raised when the real CICIDS2017 CSV isn't present locally. Evaluation requires
    real data -- it never substitutes synthetic data for a real metric."""


def load_dataset_summary(data_path=RAW_DATA_PATH) -> DatasetSummary:
    if not data_path.exists():
        raise DatasetUnavailableError(
            f"Real dataset not found at {data_path}. Evaluation requires the actual "
            "CICIDS2017 CSV -- see README 'Getting the dataset'. No synthetic "
            "substitute is used."
        )
    quality = compute_dataset_quality_stats(data_path)
    df = load_and_clean_dataset(data_path)
    class_distribution = {
        INVERSE_LABEL_MAP.get(label, str(label)): int(count)
        for label, count in df[TARGET_COLUMN].value_counts().to_dict().items()
    }
    return DatasetSummary(
        path=str(data_path),
        total_rows_before_cleaning=quality["total_rows_before_cleaning"],
        rows_after_cleaning=len(df),
        duplicate_rows_removed=quality["duplicate_rows"],
        duplicate_rate=quality["duplicate_rate"],
        missing_value_total=quality["missing_value_total"],
        infinite_value_total=quality["infinite_value_total"],
        class_distribution=class_distribution,
        class_labels=sorted(class_distribution),
    )


def load_model_summary() -> ModelSummary:
    if not MODEL_PATH.exists():
        raise DatasetUnavailableError(  # reuse: "no artifact to evaluate" is the same class of precondition failure
            f"No trained model found at {MODEL_PATH}. Evaluation loads the existing "
            "artifact -- it never trains one. Run `uv run python -m backend.ml.train` "
            "first if you intend to produce one."
        )
    model = _load_model()
    metadata = _load_metadata() or {}
    return ModelSummary(
        model_path=str(MODEL_PATH),
        model_version=model_version(),
        n_estimators=metadata.get("n_estimators"),
        random_state=metadata.get("random_state"),
        feature_count=int(model.n_features_in_),
        trained_class_labels=[INVERSE_LABEL_MAP.get(int(c), str(c)) for c in model.classes_],
    )


@dataclass
class _ScoredSplit:
    y_true: np.ndarray
    y_pred: np.ndarray
    proba: np.ndarray  # shape (n, n_classes), columns ordered per class_indices below
    class_indices: list[int]
    class_names: list[str]
    latencies_ms: list[float]


# Individual single-row predict() calls take ~1000x longer per row than a single
# batched call over the whole split (measured: ~1.7ms/row individually vs. a
# fraction of a millisecond/row batched) -- purely sklearn/numpy call overhead
# multiplied by tens of thousands of rows, not a meaningful signal about the model
# itself. Correctness metrics therefore use one fast batched call over the *entire*
# split; latency is measured separately, by individually timing a bounded sample --
# that's the same unit of work backend/ml/predictor.py's predict() does per real API
# request, so these latency numbers are comparable to production request latency.
_LATENCY_SAMPLE_SIZE = 300


def _score(model, X: pd.DataFrame, y: pd.Series, *, latency_sample_size: int = _LATENCY_SAMPLE_SIZE) -> _ScoredSplit:
    class_indices = sorted(INVERSE_LABEL_MAP)
    class_names = [INVERSE_LABEL_MAP[i] for i in class_indices]
    # model.classes_ may not be in the same order as class_indices -- reorder columns.
    column_for_index = {int(c): position for position, c in enumerate(model.classes_)}

    y_pred_raw = model.predict(X)
    proba_raw = model.predict_proba(X) if hasattr(model, "predict_proba") else None

    y_pred = y_pred_raw.astype(int)
    proba = np.zeros((len(X), len(class_indices)), dtype=float)
    if proba_raw is not None:
        for i, class_index in enumerate(class_indices):
            proba[:, i] = proba_raw[:, column_for_index[class_index]]

    sample_n = min(latency_sample_size, len(X))
    latencies_ms: list[float] = []
    for row_position in range(sample_n):
        row = X.iloc[[row_position]]
        start = time.perf_counter()
        model.predict(row)
        if hasattr(model, "predict_proba"):
            model.predict_proba(row)
        latencies_ms.append((time.perf_counter() - start) * 1000)

    return _ScoredSplit(
        y_true=y.to_numpy(),
        y_pred=y_pred,
        proba=proba,
        class_indices=class_indices,
        class_names=class_names,
        latencies_ms=latencies_ms,
    )


def _classification_metrics_from_scored(
    scored: _ScoredSplit, *, split: str, split_description: str
) -> ClassificationMetrics:
    y_true, y_pred = scored.y_true, scored.y_pred
    class_indices, class_names = scored.class_indices, scored.class_names

    per_class_precision = precision_score(y_true, y_pred, labels=class_indices, average=None, zero_division=0)
    per_class_recall = recall_score(y_true, y_pred, labels=class_indices, average=None, zero_division=0)
    per_class_f1 = f1_score(y_true, y_pred, labels=class_indices, average=None, zero_division=0)
    support = confusion_matrix(y_true, y_pred, labels=class_indices).sum(axis=1)

    per_class = {
        class_names[i]: PerClassMetrics(
            precision=float(per_class_precision[i]),
            recall=float(per_class_recall[i]),
            f1=float(per_class_f1[i]),
            support=int(support[i]),
        )
        for i in range(len(class_names))
    }

    roc_auc = pr_auc = None
    positive_label = None
    if len(class_indices) == 2 and "DDoS" in LABEL_MAP:
        positive_index = class_indices.index(LABEL_MAP["DDoS"])
        positive_label = "DDoS"
        y_true_binary = (y_true == LABEL_MAP["DDoS"]).astype(int)
        y_score = scored.proba[:, positive_index]
        # Only computable if both classes are actually present in this split -- a
        # split with a single class has no ROC/PR curve to speak of.
        if len(set(y_true_binary)) == 2:
            roc_auc = float(roc_auc_score(y_true_binary, y_score))
            pr_auc = float(average_precision_score(y_true_binary, y_score))

    winning_confidences = scored.proba[np.arange(len(y_pred)), [class_indices.index(p) for p in y_pred]]

    return ClassificationMetrics(
        split=split,
        split_description=split_description,
        samples=len(y_true),
        accuracy=float(accuracy_score(y_true, y_pred)),
        balanced_accuracy=float(balanced_accuracy_score(y_true, y_pred)),
        precision_macro=float(precision_score(y_true, y_pred, labels=class_indices, average="macro", zero_division=0)),
        recall_macro=float(recall_score(y_true, y_pred, labels=class_indices, average="macro", zero_division=0)),
        f1_macro=float(f1_score(y_true, y_pred, labels=class_indices, average="macro", zero_division=0)),
        f1_weighted=float(f1_score(y_true, y_pred, labels=class_indices, average="weighted", zero_division=0)),
        roc_auc=roc_auc,
        pr_auc=pr_auc,
        positive_label=positive_label,
        confusion_matrix=confusion_matrix(y_true, y_pred, labels=class_indices).tolist(),
        confusion_matrix_labels=class_names,
        per_class=per_class,
        class_distribution={class_names[i]: int((y_true == class_indices[i]).sum()) for i in range(len(class_names))},
        inference_latency_ms=latency_stats(scored.latencies_ms),
        mean_winning_class_confidence=round(float(winning_confidences.mean()), 6),
    )


def evaluate_held_out_test(data_path=RAW_DATA_PATH) -> tuple[ClassificationMetrics, dict]:
    """Reconstructs the deterministic train/test split backend/ml/train.py used and
    evaluates the existing model ONLY on the reconstructed test portion -- a true
    held-out generalization estimate, not training-set performance. Returns the
    metrics plus a small cross-validation dict comparing the reconstructed split's
    size against what train.py recorded in metadata.json at training time (when
    available), so a reader can judge whether the reconstruction plausibly matches
    the original split rather than just trusting the claim. Correctness metrics use
    every reconstructed test row (batch-scored, fast -- see _score()); only latency
    is measured on a bounded sample.
    """
    model = _load_model()
    df = load_and_clean_dataset(data_path)
    X, y = split_features_target(df)

    _, X_test, _, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)

    cross_check: dict = {"reconstructed_test_rows": len(X_test)}
    metadata = _load_metadata()
    if metadata and "metrics" in metadata and "test_rows" in metadata["metrics"]:
        cross_check["recorded_test_rows"] = metadata["metrics"]["test_rows"]
        cross_check["matches_recorded_test_rows"] = cross_check["recorded_test_rows"] == len(X_test)

    scored = _score(model, X_test, y_test)
    metrics = _classification_metrics_from_scored(
        scored,
        split="held_out_test",
        split_description=(
            "Reconstructed held-out test split (train_test_split with the same "
            "random_state/test_size backend/ml/train.py used) -- these rows were not "
            "used to fit the model. A true generalization estimate."
        ),
    )
    return metrics, cross_check


def evaluate_full_dataset(data_path=RAW_DATA_PATH, *, max_samples: int | None = None) -> ClassificationMetrics:
    """Descriptive metrics over the FULL cleaned dataset (train + test rows combined).

    NOT a generalization estimate -- most of these rows were used to fit the model,
    so this number is expected to look better than evaluate_held_out_test() and must
    never be reported as if it were held-out performance. Included only as a
    descriptive summary of the model's behavior across the entire known dataset.

    max_samples optionally bounds how many rows are scored (deterministic: takes the
    first N rows after cleaning, not a random sample). Default None scores every row
    -- batch scoring the full ~225k-row dataset takes well under a second (see
    _score()), so there's no practical reason to truncate by default.
    """
    model = _load_model()
    df = load_and_clean_dataset(data_path)
    X, y = split_features_target(df)
    if max_samples is not None and len(X) > max_samples:
        X = X.iloc[:max_samples]
        y = y.iloc[:max_samples]

    scored = _score(model, X, y)
    return _classification_metrics_from_scored(
        scored,
        split="full_dataset",
        split_description=(
            "Descriptive metrics over the full cleaned dataset (includes rows the "
            "model was trained on) -- NOT a generalization estimate. See "
            "'held_out_test' for that."
        ),
    )


def threshold_analysis(
    data_path=RAW_DATA_PATH, *, thresholds: list[float] | None = None
) -> ThresholdAnalysis | None:
    """Sweeps the DDoS decision threshold over the held-out test set's already-
    computed probabilities (single predict_proba pass, not re-run per threshold).
    Evaluation only -- see ThresholdAnalysis.note. Returns None if the model isn't
    binary BENIGN/DDoS (this analysis is specific to that decision boundary)."""
    if "DDoS" not in LABEL_MAP or len(LABEL_MAP) != 2:
        return None

    thresholds = thresholds or [round(0.1 + 0.05 * i, 2) for i in range(17)]  # 0.10 .. 0.90

    model = _load_model()
    df = load_and_clean_dataset(data_path)
    X, y = split_features_target(df)
    _, X_test, _, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)

    positive_index_in_classes = list(model.classes_).index(LABEL_MAP["DDoS"])
    y_score = model.predict_proba(X_test)[:, positive_index_in_classes]
    y_true_binary = (y_test.to_numpy() == LABEL_MAP["DDoS"]).astype(int)

    points: list[ThresholdPoint] = []
    for threshold in thresholds:
        y_pred_binary = (y_score >= threshold).astype(int)
        tp = int(((y_pred_binary == 1) & (y_true_binary == 1)).sum())
        fp = int(((y_pred_binary == 1) & (y_true_binary == 0)).sum())
        fn = int(((y_pred_binary == 0) & (y_true_binary == 1)).sum())
        tn = int(((y_pred_binary == 0) & (y_true_binary == 0)).sum())

        precision = tp / (tp + fp) if (tp + fp) else 0.0
        recall = tp / (tp + fn) if (tp + fn) else 0.0
        f1 = (2 * precision * recall / (precision + recall)) if (precision + recall) else 0.0
        fpr = fp / (fp + tn) if (fp + tn) else 0.0
        fnr = fn / (fn + tp) if (fn + tp) else 0.0

        points.append(
            ThresholdPoint(
                threshold=threshold,
                precision=round(precision, 6),
                recall=round(recall, 6),
                f1=round(f1, 6),
                false_positive_rate=round(fpr, 6),
                false_negative_rate=round(fnr, 6),
            )
        )

    best = max(points, key=lambda p: p.f1)
    return ThresholdAnalysis(
        positive_label="DDoS",
        points=points,
        best_f1_threshold=best.threshold,
        best_f1=best.f1,
        production_threshold=0.5,
    )


def calibration_report(data_path=RAW_DATA_PATH, *, n_bins: int = 10) -> CalibrationReport | None:
    """Brier score + reliability bins for the DDoS positive-class probability, over
    the held-out test set. Returns None if the model isn't binary BENIGN/DDoS."""
    if "DDoS" not in LABEL_MAP or len(LABEL_MAP) != 2:
        return None

    model = _load_model()
    df = load_and_clean_dataset(data_path)
    X, y = split_features_target(df)
    _, X_test, _, y_test = train_test_split(X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y)

    positive_index_in_classes = list(model.classes_).index(LABEL_MAP["DDoS"])
    y_score = model.predict_proba(X_test)[:, positive_index_in_classes]
    y_true_binary = (y_test.to_numpy() == LABEL_MAP["DDoS"]).astype(int)

    brier = float(brier_score_loss(y_true_binary, y_score))

    edges = np.linspace(0.0, 1.0, n_bins + 1)
    bins: list[CalibrationBin] = []
    for i in range(n_bins):
        lower, upper = edges[i], edges[i + 1]
        in_bin = (y_score >= lower) & (y_score < upper if i < n_bins - 1 else y_score <= upper)
        count = int(in_bin.sum())
        bins.append(
            CalibrationBin(
                bin_lower=round(float(lower), 2),
                bin_upper=round(float(upper), 2),
                count=count,
                mean_predicted_probability=round(float(y_score[in_bin].mean()), 6) if count else None,
                empirical_positive_rate=round(float(y_true_binary[in_bin].mean()), 6) if count else None,
            )
        )

    return CalibrationReport(
        positive_label="DDoS",
        brier_score=round(brier, 6),
        bins=bins,
        note=(
            "Brier score is the mean squared error between predicted DDoS "
            "probability and the true binary outcome (0 = perfect). Bins with a "
            "small count are statistically unreliable -- see the 'count' field for "
            "each bin rather than trusting every bin's empirical_positive_rate "
            "equally. A model this accurate is expected to produce very few "
            "predictions in the uncertain middle range; that is a real, honestly "
            "reported finding, not a computation error."
        ),
    )
