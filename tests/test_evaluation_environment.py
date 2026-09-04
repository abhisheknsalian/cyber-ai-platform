"""Phase 16: tests for backend/evaluation/environment.py."""

from __future__ import annotations

from unittest.mock import patch

from backend.evaluation.environment import _ollama_cli_version, capture_environment_info
from backend.ml.config import RANDOM_STATE


def test_capture_environment_info_returns_real_non_empty_values():
    info = capture_environment_info()
    assert info.os
    assert info.python_version
    assert len(info.hostname_hash) == 12
    assert info.random_seed == RANDOM_STATE  # imported from backend/ml/config.py, never duplicated
    assert info.ollama_model


def test_hostname_is_hashed_not_stored_raw():
    import platform

    info = capture_environment_info()
    assert platform.node() not in info.hostname_hash or platform.node() == ""


def test_ollama_cli_version_is_none_when_binary_not_on_path():
    with patch("backend.evaluation.environment.shutil.which", return_value=None):
        assert _ollama_cli_version() is None


def test_ollama_cli_version_returns_none_on_subprocess_failure():
    import subprocess

    with patch("backend.evaluation.environment.shutil.which", return_value="/usr/bin/ollama"):
        with patch("backend.evaluation.environment.subprocess.run", side_effect=subprocess.TimeoutExpired("ollama", 5)):
            assert _ollama_cli_version() is None


def test_report_round_trips_through_json():
    from backend.evaluation.schemas import EnvironmentInfo

    info = capture_environment_info()
    reloaded = EnvironmentInfo.model_validate(info.model_dump())
    assert reloaded.random_seed == info.random_seed
