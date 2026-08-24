"""Points the RAG config at an isolated, temporary Chroma collection before any
`backend.*` module is imported, so tests never touch the real rag/chroma_db/.
"""

import os
import shutil
import tempfile
from pathlib import Path

_TEST_CHROMA_DIR = Path(tempfile.mkdtemp(prefix="cyber_ai_test_chroma_"))
os.environ["CHROMA_PERSIST_DIR"] = str(_TEST_CHROMA_DIR)
os.environ["CHROMA_COLLECTION"] = "test_threat_intel"

import pytest  # noqa: E402

from backend.rag.ingestion import build_vector_store  # noqa: E402


@pytest.fixture(scope="session", autouse=True)
def _test_vector_store():
    build_vector_store()
    yield
    shutil.rmtree(_TEST_CHROMA_DIR, ignore_errors=True)
