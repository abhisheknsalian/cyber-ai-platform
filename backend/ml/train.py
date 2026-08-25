"""Train the DDoS/BENIGN Random Forest classifier and save the artifact locally.

    uv run python -m backend.ml.train

Requires the CICIDS2017 "Friday-Afternoon-DDoS" CSV at RAW_DATA_PATH (see README
"ML Detection Pipeline" for how to obtain it -- it is not committed to this repo).

Training is intentionally separate from inference (backend/ml/predictor.py): this
script is the only place the model is ever fit. The API only ever loads the saved
artifact.
"""

import json
from datetime import datetime, timezone

import joblib
from sklearn.ensemble import RandomForestClassifier
from sklearn.metrics import (
    accuracy_score,
    classification_report,
    confusion_matrix,
    f1_score,
    precision_score,
    recall_score,
)
from sklearn.model_selection import train_test_split

from backend.ml.config import (
    INVERSE_LABEL_MAP,
    METADATA_PATH,
    MODEL_DIR,
    MODEL_PATH,
    N_ESTIMATORS,
    RANDOM_STATE,
    RAW_DATA_PATH,
    TARGET_COLUMN,
    TEST_SIZE,
)
from backend.ml.preprocessing import compute_dataset_quality_stats, load_and_clean_dataset, split_features_target


def compute_classification_metrics(y_test, y_pred) -> dict:
    """Class-count-agnostic evaluation (Phase 10): works whether the model was
    trained on 2 classes (today's real BENIGN/DDoS data) or more (whenever real
    multi-class data is available -- see README "ML Detection Pipeline"). Class
    ordering/names are derived from INVERSE_LABEL_MAP (backend/ml/config.py), the
    same single source of truth used everywhere else, rather than a hardcoded
    ["BENIGN", "DDoS"] list.
    """
    class_indices = sorted(INVERSE_LABEL_MAP)
    class_names = [INVERSE_LABEL_MAP[index] for index in class_indices]

    report_text = classification_report(
        y_test, y_pred, labels=class_indices, target_names=class_names, zero_division=0
    )
    matrix = confusion_matrix(y_test, y_pred, labels=class_indices).tolist()

    per_class_precision = precision_score(y_test, y_pred, labels=class_indices, average=None, zero_division=0)
    per_class_recall = recall_score(y_test, y_pred, labels=class_indices, average=None, zero_division=0)
    per_class_f1 = f1_score(y_test, y_pred, labels=class_indices, average=None, zero_division=0)

    per_class = {
        class_names[i]: {
            "precision": float(per_class_precision[i]),
            "recall": float(per_class_recall[i]),
            "f1": float(per_class_f1[i]),
        }
        for i in range(len(class_names))
    }

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_macro": precision_score(y_test, y_pred, labels=class_indices, average="macro", zero_division=0),
        "recall_macro": recall_score(y_test, y_pred, labels=class_indices, average="macro", zero_division=0),
        "f1_macro": f1_score(y_test, y_pred, labels=class_indices, average="macro", zero_division=0),
        "f1_weighted": f1_score(y_test, y_pred, labels=class_indices, average="weighted", zero_division=0),
        "per_class": per_class,
        "confusion_matrix": matrix,
        "confusion_matrix_labels": class_names,
    }
    return metrics, report_text


def train(data_path=RAW_DATA_PATH, model_path=MODEL_PATH, metadata_path=METADATA_PATH):
    if not data_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {data_path}. See README 'ML Detection Pipeline' "
            "for how to obtain the CICIDS2017 Friday-Afternoon-DDoS CSV, or set "
            "DDOS_DATASET_PATH to point at it."
        )

    quality_stats = compute_dataset_quality_stats(data_path)
    print(
        f"Raw dataset quality: {quality_stats['total_rows_before_cleaning']} rows, "
        f"{quality_stats['duplicate_rows']} duplicate ({quality_stats['duplicate_rate']:.2%}), "
        f"{quality_stats['missing_value_total']} missing value(s), "
        f"{quality_stats['infinite_value_total']} infinite value(s)"
    )

    df = load_and_clean_dataset(data_path)

    class_distribution = {
        INVERSE_LABEL_MAP.get(label, str(label)): count
        for label, count in df[TARGET_COLUMN].value_counts().to_dict().items()
    }
    print(f"Class distribution after cleaning: {class_distribution}")

    X, y = split_features_target(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Train rows: {len(X_train)}  Test rows: {len(X_test)}")

    model = RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    metrics, report_text = compute_classification_metrics(y_test, y_pred)
    metrics["class_distribution"] = class_distribution
    metrics["train_rows"] = len(X_train)
    metrics["test_rows"] = len(X_test)

    print("\nClassification report:\n" + report_text)
    print(f"Confusion matrix {metrics['confusion_matrix_labels']}: {metrics['confusion_matrix']}")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_estimators": N_ESTIMATORS,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "feature_count": len(X.columns),
        # The classes this specific artifact was actually trained on, sorted by
        # label index -- explicit and inspectable, rather than implied only by
        # LABEL_MAP (which describes *configured* labels, not necessarily what any
        # one past training run used, if LABEL_MAP is ever extended later).
        "class_labels": metrics["confusion_matrix_labels"],
        "dataset_quality": quality_stats,
        "metrics": metrics,
        "classification_report": report_text,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str))

    print(f"\nModel saved to {model_path}")
    print(f"Metadata saved to {metadata_path}")

    return model, metrics


if __name__ == "__main__":
    train()
