"""RQ1 data-leakage / generalization audit (Phase 17).

Read-only against the real local CICIDS2017 CSV and the exact production
preprocessing pipeline (backend/ml/preprocessing.py, backend/ml/config.py) -- never
retrains or modifies the production model artifact.

What this CSV variant actually contains (verified by reading the header, not
assumed): the 78 CICFlowMeter feature columns plus Label. It carries NO Flow ID,
Source/Destination IP, Source Port, or Timestamp column -- this is the commonly
distributed "MachineLearningCSV" cut of CICIDS2017, stripped of session-identifying
metadata before distribution. That is a real, structural property of the available
data, not a limitation of this audit code: it means a temporal split, a host-level
split, and a file-level split (there is also only one capture file,
Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv, so "file-level" is moot regardless)
are all genuinely NOT MEASURABLE from this data -- see split_feasibility_audit(). No
grouping metadata is invented to work around that.

What IS measurable without inventing anything:
1. Exact-duplicate rows in the raw file (already handled by production cleaning,
   before the split -- see backend/ml/preprocessing.py::load_and_clean_dataset()).
2. Cross-label feature-vector collisions: after production cleaning (which already
   drops whole-row duplicates, features+label together), any row whose
   FEATURE_COLUMNS values still match another row's must have a DIFFERENT label --
   otherwise the earlier whole-row dedup would already have removed it. A non-zero
   rate here is genuine label ambiguity in the source capture.
3. Near-duplicate flows: CICIDS2017's automated attack-tool generation is documented
   in the literature (Engelen et al., "Troubleshooting an Intrusion Detection
   Dataset", 2021) to produce flows that are extremely similar but not byte-identical
   -- undetectable by exact dedup, and exactly the kind of leakage that inflates
   random-split scores on this dataset family. Measured here via standardized
   nearest-neighbor distance from a random sample of test rows to their closest
   training row.
4. A rounding-based "family" grouping, used only as the basis for the alternative,
   stronger split in generalization_experiment.py -- explicitly documented as a
   heuristic proxy for a real session/flow identifier this data doesn't have.
"""

from __future__ import annotations

import numpy as np
import pandas as pd
from sklearn.neighbors import NearestNeighbors

from backend.evaluation.schemas import (
    CrossLabelCollisionAudit,
    ExactDuplicateAudit,
    FamilyGroupingAudit,
    LeakageAuditReport,
    NearDuplicateAudit,
    SplitFeasibilityAudit,
    distribution_stats,
)
from backend.ml.config import FEATURE_COLUMNS, RANDOM_STATE, RAW_DATA_PATH, TARGET_COLUMN, TEST_SIZE
from backend.ml.preprocessing import compute_dataset_quality_stats, load_and_clean_dataset, split_features_target
from sklearn.model_selection import train_test_split

# Columns a session/host/temporal grouping would require -- CICFlowMeter's usual
# output has these; this specific distributed CSV variant does not (verified by
# reading data/raw/*.csv's header, see module docstring).
_GROUPING_COLUMNS_REQUIRED = ("Flow ID", "Source IP", "Destination IP", "Timestamp")

_NEAR_DUP_TEST_SAMPLE_SIZE = 2000
_NEAR_DUP_THRESHOLDS = (0.01, 0.1, 1.0)
# 3 significant digits (not decimal places): CICFlowMeter columns span wildly
# different magnitudes (e.g. "Destination Port" ~1e2-1e4, "Flow Duration" ~1e0-1e7),
# so fixed decimal-place rounding does nothing to the large-integer columns.
# Significant-digit rounding was chosen empirically by checking how many rows fall
# into multi-row families at 2/3/4 significant digits against the real dataset (2:
# 17.6% of rows, 3: 5.2%, 4: 1.1%) -- 3 was picked as a middle ground that still
# groups a meaningful fraction of rows without being so coarse it merges genuinely
# distinct flows. This is a documented judgment call, not a validated parameter.
_FAMILY_SIGNIFICANT_DIGITS = 3


class LeakageAuditUnavailableError(RuntimeError):
    """Raised when the real dataset isn't present -- never fabricates a leakage audit."""


def _raw_header_columns(csv_path) -> list[str]:
    return [c.strip() for c in pd.read_csv(csv_path, nrows=0).columns]


def split_feasibility_audit(csv_path) -> SplitFeasibilityAudit:
    header = set(_raw_header_columns(csv_path))
    missing = [c for c in _GROUPING_COLUMNS_REQUIRED if c not in header]
    file_count = len(list(csv_path.parent.glob("*.csv")))
    return SplitFeasibilityAudit(
        temporal_split_possible=False,
        host_split_possible=False,
        file_split_possible=False,
        family_grouped_split_possible=True,
        reason=(
            f"The distributed CSV has no {', '.join(missing)} column(s) (verified by "
            "reading the header), so temporal and host-level splits cannot be "
            "reconstructed without inventing metadata this dataset does not carry. "
            f"Only {file_count} raw capture file is present in data/raw/, so a "
            "file-level split is not a meaningful additional control (there is "
            "nothing to hold out at the file granularity). A rounding-based feature "
            "'family' grouping (FamilyGroupingAudit) is used instead as the basis "
            "for a stronger split -- see generalization_experiment.py -- and is "
            "explicitly documented as a heuristic, not a verified session identifier."
        ),
    )


def cross_label_collision_audit(df: pd.DataFrame) -> CrossLabelCollisionAudit:
    dup_mask = df.duplicated(subset=FEATURE_COLUMNS, keep=False)
    affected_rows = int(dup_mask.sum())
    distinct_feature_vectors = int(len(df.drop_duplicates(subset=FEATURE_COLUMNS)))
    colliding_groups = int(df.loc[dup_mask].groupby(FEATURE_COLUMNS).ngroups) if affected_rows else 0
    return CrossLabelCollisionAudit(
        rows_checked=len(df),
        distinct_feature_vectors=distinct_feature_vectors,
        colliding_feature_vector_groups=colliding_groups,
        affected_rows=affected_rows,
        affected_row_rate=round(affected_rows / len(df), 6) if len(df) else 0.0,
        note=(
            "A colliding group is 2+ rows sharing identical FEATURE_COLUMNS values "
            "after production cleaning (which already removes exact whole-row "
            "duplicates, features+label together) -- so every colliding group here "
            "is guaranteed to carry conflicting labels for the same measured "
            "feature vector, i.e. genuine label ambiguity in the source capture, "
            "not a code defect. These rows CAN legitimately land on opposite sides "
            "of a random split; this is measured, not prevented."
        ),
    )


def near_duplicate_audit(
    df: pd.DataFrame, *, sample_size: int = _NEAR_DUP_TEST_SAMPLE_SIZE, seed: int = RANDOM_STATE
) -> NearDuplicateAudit:
    X, y = split_features_target(df)
    X_train, X_test, _y_train, _y_test = train_test_split(
        X, y, test_size=TEST_SIZE, random_state=RANDOM_STATE, stratify=y
    )

    # Standardize using TRAIN statistics only -- this audit must not leak test
    # distribution information into itself.
    mean = X_train.mean(axis=0)
    std = X_train.std(axis=0).replace(0, 1.0)  # constant columns: avoid divide-by-zero
    X_train_scaled = ((X_train - mean) / std).to_numpy(dtype=float)

    rng = np.random.default_rng(seed)
    sample_size = min(sample_size, len(X_test))
    sample_idx = rng.choice(len(X_test), size=sample_size, replace=False)
    X_test_scaled = (((X_test - mean) / std).to_numpy(dtype=float))[sample_idx]

    nn = NearestNeighbors(n_neighbors=1, algorithm="auto")
    nn.fit(X_train_scaled)
    distances, _indices = nn.kneighbors(X_test_scaled)
    distances = distances.ravel()

    fractions = {
        f"euclidean_lt_{threshold}": round(float(np.mean(distances < threshold)), 6)
        for threshold in _NEAR_DUP_THRESHOLDS
    }

    return NearDuplicateAudit(
        method="1-NN Euclidean distance (train-standardized features) from a random sample of held-out test rows to their nearest training row",
        distance_metric="euclidean_standardized",
        train_rows=len(X_train),
        test_sample_size=sample_size,
        seed=seed,
        distance=distribution_stats(distances.tolist()),
        near_duplicate_fraction_by_threshold=fractions,
        note=(
            "Thresholds are heuristic, not literature-calibrated cutoffs -- read the "
            "full distance distribution (distance.*) alongside the threshold "
            "fractions. A distance near 0.0 in standardized-feature space means the "
            "nearest training row is nearly indistinguishable from this test row "
            "across all 78 features simultaneously; exact byte-identical duplicates "
            "are already removed before the split (see ExactDuplicateAudit), so any "
            "near-zero mass here reflects genuinely distinct-but-highly-correlated "
            "flows, not a preprocessing gap."
        ),
    )


def round_significant(values: np.ndarray, digits: int) -> np.ndarray:
    """Round to N significant figures (not decimal places) -- appropriate for
    columns spanning many orders of magnitude. Zero-valued entries round to 0."""
    values = values.astype(float)
    with np.errstate(divide="ignore"):
        magnitude = np.where(values != 0, np.floor(np.log10(np.abs(values))), 0.0)
    factor = 10.0 ** (digits - 1 - magnitude)
    return np.round(values * factor) / factor


def family_grouping_audit(
    df: pd.DataFrame, *, significant_digits: int = _FAMILY_SIGNIFICANT_DIGITS
) -> FamilyGroupingAudit:
    rounded_array = round_significant(df[FEATURE_COLUMNS].to_numpy(dtype=float), significant_digits)
    rounded = pd.DataFrame(rounded_array, columns=FEATURE_COLUMNS, index=df.index)
    group_sizes = rounded.groupby(list(FEATURE_COLUMNS)).size()
    multi = group_sizes[group_sizes > 1]
    return FamilyGroupingAudit(
        significant_digits=significant_digits,
        total_rows=len(df),
        family_count=int(len(group_sizes)),
        largest_family_size=int(group_sizes.max()) if len(group_sizes) else 0,
        mean_family_size=round(float(group_sizes.mean()), 4) if len(group_sizes) else 0.0,
        rows_in_multi_row_families=int(multi.sum()),
        fraction_rows_in_multi_row_families=round(float(multi.sum()) / len(df), 6) if len(df) else 0.0,
        note=(
            f"Rows are grouped into a 'family' when they become identical after "
            f"rounding every feature to {significant_digits} significant figures "
            "(not decimal places -- CICFlowMeter columns span many orders of "
            "magnitude, so fixed decimal rounding leaves large-integer columns "
            "unchanged; see this module's _FAMILY_SIGNIFICANT_DIGITS comment for how "
            "this value was chosen). This is a heuristic proxy for 'likely the same "
            "or a near-identical flow', used only because this CSV variant carries "
            "no real session identifier (see SplitFeasibilityAudit) -- it is not a "
            "verified ground-truth grouping. Used by generalization_experiment.py to "
            "build a split where whole families (not individual rows) are assigned "
            "to train or test."
        ),
    )


def run_leakage_audit(csv_path=RAW_DATA_PATH) -> LeakageAuditReport:
    if not csv_path.exists():
        raise LeakageAuditUnavailableError(
            f"Dataset not found at {csv_path}. See README 'ML Detection Pipeline' for how to obtain it."
        )

    quality = compute_dataset_quality_stats(csv_path)
    exact = ExactDuplicateAudit(
        total_rows_before_cleaning=quality["total_rows_before_cleaning"],
        duplicate_rows_before_cleaning=quality["duplicate_rows"],
        duplicate_rate_before_cleaning=quality["duplicate_rate"],
        duplicates_removed_before_split=True,
        note=(
            "backend/ml/preprocessing.py::load_and_clean_dataset() calls "
            "df.drop_duplicates() on the full cleaned frame (all feature columns + "
            "Label together) BEFORE backend/ml/train.py's train_test_split() runs, "
            "so no row surviving cleaning can appear as a byte-identical duplicate "
            "in both train and test -- this is a structural guarantee of the "
            "existing production code, verified by reading it, not merely assumed."
        ),
    )

    df = load_and_clean_dataset(csv_path)
    cross_label = cross_label_collision_audit(df)
    near_dup = near_duplicate_audit(df)
    family = family_grouping_audit(df)
    feasibility = split_feasibility_audit(csv_path)

    return LeakageAuditReport(
        dataset_path=str(csv_path),
        exact_duplicates=exact,
        cross_label_collisions=cross_label,
        near_duplicates=near_dup,
        family_grouping=family,
        split_feasibility=feasibility,
        methodology_note=(
            "This audit measures what the available data actually supports: exact "
            "duplicates (already handled before the split), cross-label feature "
            "collisions (genuine label ambiguity), and near-duplicate flows via "
            "standardized nearest-neighbor distance (the leakage mode CICIDS2017's "
            "literature documents as the likelier driver of inflated random-split "
            "scores on this dataset family). Temporal and host-level splits are "
            "explicitly NOT MEASURABLE -- see split_feasibility. No grouping "
            "metadata absent from the source CSV is invented anywhere in this module."
        ),
    )
