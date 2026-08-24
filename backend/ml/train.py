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
    METADATA_PATH,
    MODEL_DIR,
    MODEL_PATH,
    N_ESTIMATORS,
    RANDOM_STATE,
    RAW_DATA_PATH,
    TARGET_COLUMN,
    TEST_SIZE,
)
from backend.ml.preprocessing import load_and_clean_dataset, split_features_target


def train(data_path=RAW_DATA_PATH, model_path=MODEL_PATH, metadata_path=METADATA_PATH):
    if not data_path.exists():
        raise FileNotFoundError(
            f"Dataset not found at {data_path}. See README 'ML Detection Pipeline' "
            "for how to obtain the CICIDS2017 Friday-Afternoon-DDoS CSV, or set "
            "DDOS_DATASET_PATH to point at it."
        )

    df = load_and_clean_dataset(data_path)

    class_distribution = df[TARGET_COLUMN].value_counts().to_dict()
    print(f"Class distribution after cleaning (0=BENIGN, 1=DDoS): {class_distribution}")

    X, y = split_features_target(df)

    X_train, X_test, y_train, y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )
    print(f"Train rows: {len(X_train)}  Test rows: {len(X_test)}")

    model = RandomForestClassifier(n_estimators=N_ESTIMATORS, random_state=RANDOM_STATE)
    model.fit(X_train, y_train)

    y_pred = model.predict(X_test)

    report_text = classification_report(y_test, y_pred, target_names=["BENIGN", "DDoS"])
    matrix = confusion_matrix(y_test, y_pred).tolist()

    metrics = {
        "accuracy": accuracy_score(y_test, y_pred),
        "precision_macro": precision_score(y_test, y_pred, average="macro"),
        "recall_macro": recall_score(y_test, y_pred, average="macro"),
        "f1_macro": f1_score(y_test, y_pred, average="macro"),
        # DDoS is label 1 -- report it specifically since recall on the attack
        # class matters more than overall accuracy for a detection system.
        "ddos_precision": precision_score(y_test, y_pred, pos_label=1),
        "ddos_recall": recall_score(y_test, y_pred, pos_label=1),
        "ddos_f1": f1_score(y_test, y_pred, pos_label=1),
        "confusion_matrix": matrix,
        "class_distribution": class_distribution,
        "train_rows": len(X_train),
        "test_rows": len(X_test),
    }

    print("\nClassification report:\n" + report_text)
    print(f"Confusion matrix [[TN, FP], [FN, TP]]: {matrix}")

    model_path.parent.mkdir(parents=True, exist_ok=True)
    joblib.dump(model, model_path)

    metadata = {
        "trained_at": datetime.now(timezone.utc).isoformat(),
        "n_estimators": N_ESTIMATORS,
        "random_state": RANDOM_STATE,
        "test_size": TEST_SIZE,
        "feature_count": len(X.columns),
        "metrics": metrics,
        "classification_report": report_text,
    }
    metadata_path.write_text(json.dumps(metadata, indent=2, default=str))

    print(f"\nModel saved to {model_path}")
    print(f"Metadata saved to {metadata_path}")

    return model, metrics


if __name__ == "__main__":
    train()
