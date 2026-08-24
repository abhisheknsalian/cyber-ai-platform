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


def split_features_target(df: pd.DataFrame) -> tuple[pd.DataFrame, pd.Series]:
    X = df[FEATURE_COLUMNS]
    y = df[TARGET_COLUMN]
    return X, y


def features_dict_to_frame(features: dict[str, float]) -> pd.DataFrame:
    """Build a single-row, correctly-ordered DataFrame for a single inference request."""
    row = {column: features[column] for column in FEATURE_COLUMNS}
    return pd.DataFrame([row], columns=FEATURE_COLUMNS)
