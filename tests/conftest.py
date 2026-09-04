"""Points RAG + ML config at isolated, temporary locations before any `backend.*`
module is imported, so tests never touch rag/chroma_db/, models/, or require the
real 225k-row CICIDS2017 dataset.
"""

import os
import shutil
import tempfile
from pathlib import Path

_TEST_CHROMA_DIR = Path(tempfile.mkdtemp(prefix="cyber_ai_test_chroma_"))
os.environ["CHROMA_PERSIST_DIR"] = str(_TEST_CHROMA_DIR)
os.environ["CHROMA_COLLECTION"] = "test_threat_intel"

_TEST_ML_DIR = Path(tempfile.mkdtemp(prefix="cyber_ai_test_ml_"))
_TEST_DATASET_PATH = _TEST_ML_DIR / "synthetic_traffic.csv"
os.environ["DDOS_DATASET_PATH"] = str(_TEST_DATASET_PATH)
os.environ["ML_MODEL_DIR"] = str(_TEST_ML_DIR / "models")

# Isolated SQLite file per test run (Phase 13's users table) -- schema is created
# directly from the ORM models below rather than via Alembic, the standard shortcut
# for tests (see backend/db/session.py / alembic/env.py for how the app and real
# deployments provision this instead).
_TEST_DB_DIR = Path(tempfile.mkdtemp(prefix="cyber_ai_test_db_"))
os.environ["DATABASE_URL"] = f"sqlite:///{_TEST_DB_DIR / 'test.db'}"

import numpy as np  # noqa: E402
import pandas as pd  # noqa: E402
import pytest  # noqa: E402

from backend.db.base import Base  # noqa: E402
from backend.db.models import (  # noqa: E402,F401
    AnalysisRecord,
    ClassificationRecord,
    Investigation,
    User,
)
from backend.db.session import get_engine, session_scope  # noqa: E402
from backend.ml.config import FEATURE_COLUMNS  # noqa: E402
from backend.ml.train import train as train_model  # noqa: E402
from backend.rag.ingestion import build_vector_store  # noqa: E402


def _build_synthetic_dataset(path: Path, rows: int = 240, seed: int = 42) -> None:
    """A small, clearly-synthetic dataset using the real CICIDS2017 column names, used
    only to exercise the ML pipeline's plumbing (loading, cleaning, training,
    inference). It is NOT representative real traffic and its accuracy is meaningless
    -- real evaluation requires the actual CICIDS2017 file (see README).
    """
    rng = np.random.default_rng(seed)
    half = rows // 2

    df = pd.DataFrame({column: rng.exponential(scale=1000, size=rows) for column in FEATURE_COLUMNS})
    df["Label"] = ["BENIGN"] * half + ["DDoS"] * (rows - half)
    # Give DDoS rows a mild, learnable signal so the classifier beats chance --
    # tests only assert "valid prediction", never a specific accuracy number.
    df.loc[df["Label"] == "DDoS", "Flow Duration"] += 5000

    # Inject exact duplicate rows (including across the BENIGN/DDoS split) to
    # exercise the deduplication fix in preprocessing.load_and_clean_dataset.
    duplicates = df.sample(n=10, random_state=seed)
    df = pd.concat([df, duplicates], ignore_index=True)

    path.parent.mkdir(parents=True, exist_ok=True)
    df.to_csv(path, index=False)


_build_synthetic_dataset(_TEST_DATASET_PATH)


@pytest.fixture(scope="session", autouse=True)
def _test_vector_store():
    build_vector_store()
    yield
    shutil.rmtree(_TEST_CHROMA_DIR, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _test_ml_model():
    train_model()
    yield
    shutil.rmtree(_TEST_ML_DIR, ignore_errors=True)


@pytest.fixture(scope="session", autouse=True)
def _test_database():
    Base.metadata.create_all(bind=get_engine())
    yield
    shutil.rmtree(_TEST_DB_DIR, ignore_errors=True)


@pytest.fixture(autouse=True)
def _reset_users_table():
    """Phase 13 added a persistent `users` table. Without a reset between tests,
    registration/login tests that reuse a username (e.g. across test_auth_register.py
    and test_session_auth.py) would collide on the unique username constraint --
    autouse so it applies globally, same pattern as _reset_rate_limiters below."""
    with session_scope() as db:
        db.query(User).delete()
    yield
    with session_scope() as db:
        db.query(User).delete()


@pytest.fixture(autouse=True)
def _reset_investigations_tables():
    """Phase 14 added investigations/classification_results/analysis_results.
    Deleting `Investigation` rows cascades to both children via ON DELETE CASCADE --
    enforced on SQLite too via the PRAGMA foreign_keys=ON connect listener in
    backend/db/session.py, without which this cascade would silently do nothing
    locally while still working on PostgreSQL. Kept as its own reset (not folded into
    _reset_users_table above) so investigation tests aren't order-coupled to it."""
    with session_scope() as db:
        db.query(Investigation).delete()
    yield
    with session_scope() as db:
        db.query(Investigation).delete()


@pytest.fixture(autouse=True)
def _reset_rate_limiters():
    """Phase 8 added in-memory rate limiting to POST /auth/login, /analyze, /classify,
    and /analyze/classification. Without a reset between every test, the many
    pre-existing tests that call those endpoints repeatedly (test_session_auth.py,
    test_api.py, test_ml_api.py, ...) would eventually trip the limiter and start
    failing with spurious 429s -- autouse so it applies globally, not just to the
    dedicated rate-limit tests."""
    from backend.rate_limit import AI_RATE_LIMIT, LOGIN_RATE_LIMIT

    LOGIN_RATE_LIMIT.reset()
    AI_RATE_LIMIT.reset()
    yield
    LOGIN_RATE_LIMIT.reset()
    AI_RATE_LIMIT.reset()
