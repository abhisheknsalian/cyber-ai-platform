"""Preprocessing shared by training (backend/ml/train.py) and inference
(backend/ml/predictor.py) so the two paths can never silently drift apart.
"""

import numpy as np
import pandas as pd

from backend.ml.config import FEATURE_COLUMNS, LABEL_MAP, TARGET_COLUMN


def load_and_clean_dataset(csv_path) -> pd.DataFrame:
    """Load the raw CICIDS2017 CSV and apply the same cleaning as the original notebook,
    plus a deduplication step the notebook was missing (see README "Data Leakage").
    """
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    df = df.replace([np.inf, -np.inf], np.nan)
    df = df.dropna()

    before = len(df)
    df = df.drop_duplicates()
    removed = before - len(df)
    print(
        f"Dropped {removed} duplicate row(s) ({removed / before:.2%} of {before}) "
        "before the train/test split to prevent identical flows leaking across splits."
    )

    df[TARGET_COLUMN] = df[TARGET_COLUMN].map(LABEL_MAP)
    if df[TARGET_COLUMN].isna().any():
        unknown = df[TARGET_COLUMN].isna().sum()
        raise ValueError(f"{unknown} row(s) had a label outside {list(LABEL_MAP)}")

    return df


def compute_dataset_quality_stats(csv_path) -> dict:
    """Read-only data-quality statistics about the *raw* dataset, computed before any
    cleaning -- duplicate/missing/infinite-value counts. Used only by
    backend/ml/train.py's metadata reporting (Phase 10); does not affect what
    load_and_clean_dataset() actually trains on.

    Deliberately reads the CSV independently rather than sharing a DataFrame with
    load_and_clean_dataset() -- that function's existing signature (and
    tests/test_ml_preprocessing.py, which calls it directly) stays completely
    unchanged. Training is an offline, manually-run batch process, so reading the
    file twice here is an acceptable, low-risk tradeoff for keeping the existing,
    tested function untouched.
    """
    df = pd.read_csv(csv_path)
    df.columns = df.columns.str.strip()

    total_rows = len(df)
    duplicate_rows = int(df.duplicated().sum())

    missing_counts = df.isna().sum()
    missing_by_column = {column: int(count) for column, count in missing_counts.items() if count > 0}

    numeric_df = df.select_dtypes(include=[np.number])
    infinite_counts = np.isinf(numeric_df).sum()
    infinite_by_column = {column: int(count) for column, count in infinite_counts.items() if count > 0}

    return {
        "total_rows_before_cleaning": total_rows,
        "duplicate_rows": duplicate_rows,
        "duplicate_rate": round(duplicate_rows / total_rows, 6) if total_rows else 0.0,
        "missing_value_total": int(missing_counts.sum()),
        "missing_values_by_column": missing_by_column,
        "infinite_value_total": int(infinite_counts.sum()),
        "infinite_values_by_column": infinite_by_column,
    }


def split_features_target(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]
    return X, y


def features_dict_to_frame(features: dict[str, float]) -> pd.DataFrame:
    """Build a single-row, correctly-ordered DataFrame for a single inference request."""
    row = {column: features[column] for column in FEATURE_COLUMNS}
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)
