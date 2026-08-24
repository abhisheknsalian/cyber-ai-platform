from backend.ml.config import RAW_DATA_PATH
from backend.ml.preprocessing import load_and_clean_dataset


def test_cleaning_removes_duplicate_rows():
    """The synthetic fixture (tests/conftest.py) intentionally injects 10 duplicate
    rows. This is the regression test for the leakage fix: the original notebook
    split without deduplicating first, letting identical rows land in both train and
    test. load_and_clean_dataset must not let any duplicates survive to the split.
    """
    df = load_and_clean_dataset(RAW_DATA_PATH)
    assert df.duplicated().sum() == 0


def test_cleaning_produces_both_classes():
    df = load_and_clean_dataset(RAW_DATA_PATH)
    assert set(df["Label"].unique()) == {0, 1}
