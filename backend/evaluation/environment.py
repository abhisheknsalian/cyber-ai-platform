"""Reproducibility metadata (Phase 16, Part G). Captured fresh at report-generation
time from the actual running environment -- never hardcoded, never assumed.
"""

from __future__ import annotations

import hashlib
import platform
import shutil
import subprocess

from backend.evaluation.schemas import EnvironmentInfo
from backend.ml.config import RANDOM_STATE
from backend.rag.config import OLLAMA_MODEL

# RANDOM_STATE (backend/ml/config.py) is the one seed this project's evaluation
# determinism actually depends on (train/test split reconstruction, ml_evaluation.py)
# -- imported, not duplicated, so this can never silently drift from the real value.
# Retrieval/LLM evaluation have no random component to seed: queries are a fixed
# list, and Chroma similarity search / Ollama generation (temperature=0, see
# backend/services/llm.py) are themselves deterministic given the same inputs.


def _ollama_cli_version() -> str | None:
    """The Ollama *server/CLI* version (distinct from the `ollama` Python client
    package, which has no __version__ attribute to report) -- best-effort: None if
    the `ollama` binary isn't on PATH, never a fabricated placeholder."""
    if shutil.which("ollama") is None:
        return None
    try:
        output = subprocess.run(["ollama", "--version"], capture_output=True, text=True, timeout=5)
        return output.stdout.strip() or output.stderr.strip() or None
    except (subprocess.SubprocessError, OSError):
        return None


def capture_environment_info() -> EnvironmentInfo:
    hostname_hash = hashlib.sha256(platform.node().encode("utf-8")).hexdigest()[:12]
    return EnvironmentInfo(
        os=platform.system(),
        os_version=platform.release(),
        python_version=platform.python_version(),
        hostname_hash=hostname_hash,
        ollama_cli_version=_ollama_cli_version(),
        ollama_model=OLLAMA_MODEL,
        random_seed=RANDOM_STATE,
    )
