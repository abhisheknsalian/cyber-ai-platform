"""Phase 18 (P0.2): tests for backend/evaluation/llm_rubric_scoring.py.

Never calls Ollama or the real evaluation pipeline -- this module only reads
hand-constructed CSV fixtures, exactly the shape a human annotator would produce.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from backend.evaluation.llm_evaluation import RUBRIC_DIMENSIONS, score_column_name, write_rubric_template
from backend.evaluation.llm_rubric_scoring import (
    RubricAnnotationError,
    render_rubric_summary_table,
    score_annotations,
)

# Mirrors llm_evaluation.py's DEFAULT_CASES shape without depending on it, so this
# test suite doesn't need a real vector store: 5 on-topic cases (indices 0-4) + 2
# negative controls (indices 5-6).
_CASES = [
    ("Explain phishing attacks", "phishing"),
    ("Explain ransomware", "ransomware"),
    ("How can DDoS attacks be mitigated?", "ddos_attack"),
    ("What are SQL injection indicators?", "sql_injection"),
    ("Explain botnet attacks", "botnet"),
    ("What is the capital of France?", None),
    ("Give me a recipe.", None),
]

_SEV_COL = score_column_name("severity_reasonableness")
_SUM_COL = score_column_name("summary_grounding_quality")
_ATK_COL = score_column_name("attack_vectors_relevance")


def _base_rows() -> list[dict]:
    return [
        {
            "case_id": i, "query": q, "category": c or "(negative control)", "severity": "High" if c else "",
            "summary": "s", "attack_vectors": "a", "retrieved_context_excerpt": "ctx", "is_negative_control": c is None,
        }
        for i, (q, c) in enumerate(_CASES)
    ]


def _write_csv(tmp_path, name: str, score_overrides: dict[int, dict[str, str]]) -> Path:
    rows = _base_rows()
    for row in rows:
        overrides = score_overrides.get(row["case_id"], {})
        row.update(overrides)
    path = tmp_path / name
    write_rubric_template(rows, path)
    return path


def test_valid_full_annotation_computes_correct_means_and_status(tmp_path):
    overrides = {i: {_SEV_COL: 2, _SUM_COL: 1, _ATK_COL: 2} for i in range(5)}
    path = _write_csv(tmp_path, "a1.csv", overrides)

    summary = score_annotations([("annotator1", path)])

    assert summary.on_topic_case_count == 5
    assert summary.negative_control_case_count == 2
    sev = next(d for d in summary.dimensions if d.name == "severity_reasonableness")
    assert sev.mean_score == 2.0
    assert sev.status == "annotated"
    assert sev.valid_count == 5
    assert sev.invalid_count == 0
    assert sev.unscored_count == 0


def test_blank_cells_are_unscored_not_coerced_to_zero(tmp_path):
    # Only case 0 scored; cases 1-4 left blank.
    path = _write_csv(tmp_path, "a1.csv", {0: {_SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2}})
    summary = score_annotations([("annotator1", path)])

    sev = next(d for d in summary.dimensions if d.name == "severity_reasonableness")
    assert sev.valid_count == 1
    assert sev.unscored_count == 4
    assert sev.status == "partially_annotated"
    assert sev.mean_score == 2.0  # mean over VALID scores only, blanks never coerced to 0


def test_invalid_score_text_is_excluded_and_reported(tmp_path):
    path = _write_csv(tmp_path, "a1.csv", {0: {_SEV_COL: "yes", _SUM_COL: 2, _ATK_COL: 2}})
    summary = score_annotations([("annotator1", path)])

    sev = next(d for d in summary.dimensions if d.name == "severity_reasonableness")
    assert sev.invalid_count == 1
    assert sev.valid_count == 0
    invalid_entry = next(s for s in sev.scores if s.case_id == 0)
    assert invalid_entry.status == "invalid"
    assert invalid_entry.value is None
    assert invalid_entry.raw_value == "yes"


def test_negative_control_scores_are_never_counted_and_are_logged(tmp_path):
    path = _write_csv(tmp_path, "a1.csv", {5: {_SEV_COL: 2}})  # stray score on a negative control
    summary = score_annotations([("annotator1", path)])

    for dim in summary.dimensions:
        assert all(s.case_id != 5 for s in dim.scores)  # negative control never appears in any dimension's scores
    assert any("negative control" in row and "excluded" in row.lower() for row in summary.excluded_rows)


def test_unknown_case_id_row_is_excluded_and_logged(tmp_path):
    rows = _base_rows()
    rows.append({
        "case_id": 999, "query": "bogus", "category": "phishing", "severity": "High", "summary": "s",
        "attack_vectors": "a", "retrieved_context_excerpt": "ctx", "is_negative_control": False,
        _SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2,
    })
    path = tmp_path / "a1.csv"
    write_rubric_template(rows, path)

    summary = score_annotations([("annotator1", path)], cases=_CASES)
    for dim in summary.dimensions:
        assert all(s.case_id != 999 for s in dim.scores)
    assert any("999" in row for row in summary.excluded_rows)


def test_single_annotator_never_claims_inter_rater_reliability(tmp_path):
    path = _write_csv(tmp_path, "a1.csv", {i: {_SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2} for i in range(5)})
    summary = score_annotations([("annotator1", path)])

    assert summary.inter_rater is None
    assert summary.single_annotator_note is not None
    assert "annotator1" in summary.single_annotator_note
    assert "not" in summary.single_annotator_note.lower()


def test_two_annotators_computes_agreement_and_pooled_mean(tmp_path):
    path_a = _write_csv(tmp_path, "a1.csv", {i: {_SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2} for i in range(5)})
    path_b = _write_csv(tmp_path, "a2.csv", {i: {_SEV_COL: 0, _SUM_COL: 2, _ATK_COL: 2} for i in range(5)})

    summary = score_annotations([("annotator1", path_a), ("annotator2", path_b)])

    assert summary.inter_rater is not None
    sev_agreement = next(a for a in summary.inter_rater if a.dimension == "severity_reasonableness")
    assert sev_agreement.cases_compared == 5
    assert sev_agreement.percent_exact_agreement == 0.0  # 2 vs 0 on every case -- total disagreement
    assert sev_agreement.annotator_ids == ["annotator1", "annotator2"]
    assert sev_agreement.cohens_weighted_kappa is not None  # real disagreement -- kappa is well-defined here

    sev_dimension = next(d for d in summary.dimensions if d.name == "severity_reasonableness")
    assert sev_dimension.mean_score == 1.0  # pooled mean of (2,2,2,2,2,0,0,0,0,0) / 10


def test_degenerate_kappa_when_both_annotators_agree_on_a_constant_score(tmp_path):
    """Phase 18.1 audit finding: sklearn.metrics.cohen_kappa_score returns NaN (not
    an exception, not 0.0) when both annotators give the IDENTICAL CONSTANT score on
    every compared case -- zero variance in both raters means kappa's chance-
    correction divides by zero. This must never surface as a fabricated numeric
    kappa (and must never crash the RuntimeWarning-emitting sklearn call) -- it must
    be reported as cohens_weighted_kappa=None with an explanatory note, while
    percent_exact_agreement (well-defined: 1.0) is still reported normally."""
    # Both annotators score summary_grounding_quality as a constant 2 on every case.
    path_a = _write_csv(tmp_path, "a1.csv", {i: {_SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2} for i in range(5)})
    path_b = _write_csv(tmp_path, "a2.csv", {i: {_SEV_COL: 0, _SUM_COL: 2, _ATK_COL: 2} for i in range(5)})

    summary = score_annotations([("annotator1", path_a), ("annotator2", path_b)])

    summ_agreement = next(a for a in summary.inter_rater if a.dimension == "summary_grounding_quality")
    assert summ_agreement.percent_exact_agreement == 1.0  # both gave 2 on every case -- well-defined
    assert summ_agreement.cohens_weighted_kappa is None  # mathematically undefined, never fabricated as 0.0 or 1.0
    assert "undefined" in summ_agreement.note.lower()
    assert "constant" in summ_agreement.note.lower()

    # The rendered table must not crash formatting a None kappa as a float.
    table = render_rubric_summary_table(summary)
    assert "UNDEFINED" in table


def test_duplicate_annotator_id_raises():
    with pytest.raises(RubricAnnotationError):
        score_annotations([("a1", "x.csv"), ("a1", "y.csv")])


def test_missing_csv_file_raises(tmp_path):
    with pytest.raises(RubricAnnotationError):
        score_annotations([("a1", tmp_path / "does_not_exist.csv")])


def test_no_annotators_raises():
    with pytest.raises(RubricAnnotationError):
        score_annotations([])


def test_all_seven_rubric_dimensions_names_match_llm_evaluation_module():
    path_names = {name for name, _ in RUBRIC_DIMENSIONS}
    assert path_names == {"severity_reasonableness", "summary_grounding_quality", "attack_vectors_relevance"}


def test_render_rubric_summary_table_is_generated_not_hand_typed(tmp_path):
    path = _write_csv(tmp_path, "a1.csv", {i: {_SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2} for i in range(5)})
    summary = score_annotations([("annotator1", path)])
    table = render_rubric_summary_table(summary)
    assert "2.0000" in table
    assert "annotator1" in table
    assert "severity_reasonableness" in table


def test_report_round_trips_through_json(tmp_path):
    from backend.evaluation.schemas import LLMRubricAnnotationSummary

    path = _write_csv(tmp_path, "a1.csv", {0: {_SEV_COL: 2, _SUM_COL: 2, _ATK_COL: 2}})
    summary = score_annotations([("annotator1", path)])
    reloaded = LLMRubricAnnotationSummary.model_validate(summary.model_dump())
    assert reloaded.on_topic_case_count == summary.on_topic_case_count
