"""Phase 11: tests for backend/evaluation/__main__.py's report orchestration and CLI.

Runs the offline path (no --pipeline) against conftest.py's synthetic dataset/model
and real threat-intel vector store/graph -- no Ollama required, matching the CLI's
own documented default.
"""

import json
import sys
from unittest.mock import patch

import pytest

from backend.evaluation.__main__ import _build_report, main
from backend.evaluation.schemas import EvaluationReport


def test_build_report_offline_populates_dataset_model_classification_and_retrieval():
    report = _build_report(include_pipeline=False)

    assert report.dataset is not None
    assert report.model is not None
    assert "held_out_test" in report.classification
    assert "full_dataset" in report.classification
    assert report.retrieval is not None
    assert report.pipeline is None
    assert any("Pipeline benchmark skipped" in item for item in report.limitations)


def test_build_report_includes_fixed_dataset_limitation_language():
    report = _build_report(include_pipeline=False)
    assert any("BENIGN and DDoS" in item for item in report.limitations)
    assert any("not be read as general-purpose" in item for item in report.limitations)


def test_build_report_degrades_gracefully_when_dataset_unavailable():
    from backend.evaluation import __main__ as cli_module
    from backend.evaluation.ml_evaluation import DatasetUnavailableError

    with patch.object(cli_module, "load_dataset_summary", side_effect=DatasetUnavailableError("no dataset")):
        report = _build_report(include_pipeline=False)

    assert report.dataset is None
    assert report.classification == {}
    assert any("Dataset summary unavailable" in item for item in report.limitations)


def test_evaluation_report_json_round_trips():
    report = _build_report(include_pipeline=False)
    dumped = json.dumps(report.model_dump(), default=str)
    reloaded = EvaluationReport(**json.loads(dumped))

    assert reloaded.dataset.path == report.dataset.path
    assert reloaded.classification.keys() == report.classification.keys()


def test_cli_main_writes_output_file_and_returns_zero(tmp_path, monkeypatch):
    output_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["backend.evaluation", "--output", str(output_path)])

    exit_code = main()

    assert exit_code == 0
    assert output_path.exists()
    data = json.loads(output_path.read_text(encoding="utf-8"))
    assert "classification" in data
    assert "limitations" in data


def test_cli_main_without_pipeline_flag_does_not_require_ollama(tmp_path, monkeypatch):
    """Regression guard for the CLI's core promise: default invocation must not touch
    Ollama at all -- asserts generate_analysis_fragment is never called."""
    output_path = tmp_path / "report.json"
    monkeypatch.setattr(sys, "argv", ["backend.evaluation", "--output", str(output_path)])

    with patch("backend.evaluation.benchmark.generate_analysis_fragment") as mocked_llm:
        exit_code = main()

    assert exit_code == 0
    mocked_llm.assert_not_called()
