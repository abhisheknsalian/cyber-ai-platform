import os
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]

# The CICIDS2017 "Friday-Afternoon-DDoS" CSV is not committed to the repo (see README
# "ML Detection Pipeline") -- it must be placed here (or DDOS_DATASET_PATH pointed at it)
# before `uv run python -m backend.ml.train` can run.
RAW_DATA_PATH = Path(
    os.getenv(
        "DDOS_DATASET_PATH",
        str(PROJECT_ROOT / "data" / "raw" / "Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv"),
    )
)

MODEL_DIR = Path(os.getenv("ML_MODEL_DIR", str(PROJECT_ROOT / "models")))
MODEL_PATH = MODEL_DIR / "ddos_random_forest.joblib"
METADATA_PATH = MODEL_DIR / "ddos_random_forest.metadata.json"

TARGET_COLUMN = "Label"
LABEL_MAP = {"BENIGN": 0, "DDoS": 1}
INVERSE_LABEL_MAP = {index: label for label, index in LABEL_MAP.items()}

RANDOM_STATE = 42
TEST_SIZE = 0.2
N_ESTIMATORS = 100

# The exact 78 CICFlowMeter feature columns the model was trained on, in the exact
# order used for training (df.drop("Label", axis=1).columns from the original
# notebook, after `df.columns = df.columns.str.strip()`). This single list is the
# source of truth for both training (column selection) and the inference request
# schema (backend/ml/schemas.py) -- it is never duplicated by hand elsewhere.
FEATURE_COLUMNS = [
    "Destination Port",
    "Flow Duration",
    "Total Fwd Packets",
    "Total Backward Packets",
    "Total Length of Fwd Packets",
    "Total Length of Bwd Packets",
    "Fwd Packet Length Max",
    "Fwd Packet Length Min",
    "Fwd Packet Length Mean",
    "Fwd Packet Length Std",
    "Bwd Packet Length Max",
    "Bwd Packet Length Min",
    "Bwd Packet Length Mean",
    "Bwd Packet Length Std",
    "Flow Bytes/s",
    "Flow Packets/s",
    "Flow IAT Mean",
    "Flow IAT Std",
    "Flow IAT Max",
    "Flow IAT Min",
    "Fwd IAT Total",
    "Fwd IAT Mean",
    "Fwd IAT Std",
    "Fwd IAT Max",
    "Fwd IAT Min",
    "Bwd IAT Total",
    "Bwd IAT Mean",
    "Bwd IAT Std",
    "Bwd IAT Max",
    "Bwd IAT Min",
    "Fwd PSH Flags",
    "Bwd PSH Flags",
    "Fwd URG Flags",
    "Bwd URG Flags",
    "Fwd Header Length",
    "Bwd Header Length",
    "Fwd Packets/s",
    "Bwd Packets/s",
    "Min Packet Length",
    "Max Packet Length",
    "Packet Length Mean",
    "Packet Length Std",
    "Packet Length Variance",
    "FIN Flag Count",
    "SYN Flag Count",
    "RST Flag Count",
    "PSH Flag Count",
    "ACK Flag Count",
    "URG Flag Count",
    "CWE Flag Count",
    "ECE Flag Count",
    "Down/Up Ratio",
    "Average Packet Size",
    "Avg Fwd Segment Size",
    "Avg Bwd Segment Size",
    "Fwd Header Length.1",
    "Fwd Avg Bytes/Bulk",
    "Fwd Avg Packets/Bulk",
    "Fwd Avg Bulk Rate",
    "Bwd Avg Bytes/Bulk",
    "Bwd Avg Packets/Bulk",
    "Bwd Avg Bulk Rate",
    "Subflow Fwd Packets",
    "Subflow Fwd Bytes",
    "Subflow Bwd Packets",
    "Subflow Bwd Bytes",
    "Init_Win_bytes_forward",
    "Init_Win_bytes_backward",
    "act_data_pkt_fwd",
    "min_seg_size_forward",
    "Active Mean",
    "Active Std",
    "Active Max",
    "Active Min",
    "Idle Mean",
    "Idle Std",
    "Idle Max",
    "Idle Min",
]
