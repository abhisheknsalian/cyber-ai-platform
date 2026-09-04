"""Phase 18 (P0.2): reads a human annotator's filled-in copy of
`evaluation/llm_rubric_template.csv` (written by
backend/evaluation/llm_evaluation.py::write_rubric_template()) and computes summary
statistics -- INFRASTRUCTURE ONLY. This module never generates a rubric score
itself, does not call an LLM to judge anything, and never runs unless a human has
already produced a filled-in annotation CSV on disk.

Preserves the automated/human distinction structurally, not just in prose: this is a
completely separate entry point from backend/evaluation/llm_evaluation.py's
run_llm_evaluation() (which backend/evaluation/__main__.py's --llm flag calls fully
automatically) and from backend/evaluation/__main__.py's report-building flow in
general. Nothing here is wired into `uv run python -m backend.evaluation --full`;
run this module directly once a human has filled in the template:

    uv run python -m backend.evaluation.llm_rubric_scoring \\
        evaluation/llm_rubric_annotations_<annotator>.csv \\
        [evaluation/llm_rubric_annotations_<second_annotator>.csv]

Scoring rules (all enforced, all tested):
- Negative-control cases (is_negative_control=True in the template -- the 2 off-topic
  queries) are NEVER scored on any rubric dimension. There is no generated content to
  judge the quality of; the automated pipeline already separately checks that these
  cases correctly triggered insufficient_context (see
  LLMAutomatedMetrics.correct_relevance_off_topic_rate). A stray score present in a
  negative-control row is reported in `excluded_rows`, never silently used.
- A blank score cell is "unscored" -- excluded from the mean, never coerced to 0.
- A cell containing anything other than exactly "0", "1", or "2" is "invalid" --
  reported (with the original text, for audit) and excluded, never coerced.
- A dimension's `status` is "annotated" only once every on-topic case has a VALID
  score for it; "partially_annotated" if some but not all do; "not_yet_annotated" if
  none do.
- With exactly one annotator, `inter_rater` is None and a `single_annotator_note` is
  always set -- no inter-rater reliability is ever claimed from one annotator, and if
  that annotator is the thesis author, `single_annotator_note` says so explicitly.
- With two or more annotators, `inter_rater` reports percent exact agreement and
  Cohen's weighted kappa (linear weights -- appropriate for an ordinal 0/1/2 scale;
  sklearn.metrics.cohen_kappa_score(weights="linear"), not hand-rolled) per
  dimension, over the on-topic cases both annotators actually scored. No
  significance test is computed on kappa itself, or anywhere in this module -- n=5
  on-topic cases does not justify one.
"""

from __future__ import annotations

import csv
import math
import warnings
from pathlib import Path

from backend.evaluation.llm_evaluation import DEFAULT_CASES, RUBRIC_DIMENSIONS, SCALE_DESCRIPTION, score_column_name
from backend.evaluation.schemas import (
    InterRaterAgreementReport,
    LLMRubricAnnotationSummary,
    LLMRubricDimension,
    RubricCaseScore,
)

DEFAULT_SUMMARY_OUTPUT_PATH = Path("evaluation/llm_rubric_summary.json")


class RubricAnnotationError(RuntimeError):
    """Raised when a supplied annotation CSV cannot be read at all (missing file,
    unreadable encoding) -- distinct from a per-row parsing issue, which is
    reported in `excluded_rows` rather than raised."""


def _read_csv_rows(csv_path: Path) -> list[dict[str, str]]:
    if not csv_path.exists():
        raise RubricAnnotationError(f"Annotation CSV not found: {csv_path}")
    with csv_path.open(newline="", encoding="utf-8") as handle:
        return list(csv.DictReader(handle))


def _parse_case_id(raw: str | None) -> int | None:
    if raw is None:
        return None
    try:
        return int(raw.strip())
    except (TypeError, ValueError):
        return None


def _parse_score_cell(raw: str | None) -> tuple[str, int | None]:
    """Returns (status, value); status in {"unscored", "valid", "invalid"}. Never
    coerces a blank cell to 0, and never coerces an out-of-range/non-numeric cell to
    the nearest valid value."""
    if raw is None or raw.strip() == "":
        return "unscored", None
    stripped = raw.strip()
    if stripped in ("0", "1", "2"):
        return "valid", int(stripped)
    return "invalid", None


def parse_annotation_csv(
    csv_path: Path, *, annotator_id: str, cases: list[tuple[str, str | None]]
) -> tuple[dict[str, dict[int, RubricCaseScore]], list[str]]:
    """Reads ONE annotator's filled CSV. Returns (per_dimension_scores,
    excluded_row_notes) -- per_dimension_scores maps dimension name -> {case_id:
    RubricCaseScore}, covering every ON-TOPIC case_id exactly once (never a
    negative control). Never mutates csv_path; this function only reads it."""
    rows = _read_csv_rows(csv_path)
    negative_control_ids = {i for i, (_, category) in enumerate(cases) if category is None}
    on_topic_ids = {i for i in range(len(cases))} - negative_control_ids

    per_dimension: dict[str, dict[int, RubricCaseScore]] = {name: {} for name, _ in RUBRIC_DIMENSIONS}
    excluded: list[str] = []
    seen_on_topic_ids: set[int] = set()

    for row in rows:
        case_id = _parse_case_id(row.get("case_id"))
        if case_id is None or case_id not in range(len(cases)):
            excluded.append(
                f"{csv_path.name} ({annotator_id}): row with case_id={row.get('case_id')!r} does not match "
                "a known evaluated case -- excluded."
            )
            continue

        is_negative_control = case_id in negative_control_ids
        for name, _description in RUBRIC_DIMENSIONS:
            raw = row.get(score_column_name(name))
            status, value = _parse_score_cell(raw)
            if is_negative_control:
                if status == "valid":
                    excluded.append(
                        f"{csv_path.name} ({annotator_id}): case_id={case_id} is a negative control; a score "
                        f"of {value} for '{name}' was present but is EXCLUDED -- negative controls are never "
                        "scored on any rubric dimension."
                    )
                continue
            per_dimension[name][case_id] = RubricCaseScore(
                case_id=case_id,
                status=status,
                value=value,
                raw_value=raw if status == "invalid" else None,
                annotator_id=annotator_id,
            )
        if not is_negative_control:
            seen_on_topic_ids.add(case_id)

    # On-topic cases the CSV never had a row for at all -- unscored, not silently
    # absent from the report.
    for name, _description in RUBRIC_DIMENSIONS:
        for case_id in on_topic_ids - seen_on_topic_ids:
            per_dimension[name].setdefault(
                case_id, RubricCaseScore(case_id=case_id, status="unscored", annotator_id=annotator_id)
            )

    return per_dimension, excluded


def _dimension_status(valid_count: int, on_topic_case_count: int) -> str:
    if valid_count == 0:
        return "not_yet_annotated"
    if valid_count < on_topic_case_count:
        return "partially_annotated"
    return "annotated"


def _inter_rater_for_dimension(
    name: str, per_annotator: dict[str, dict[int, RubricCaseScore]]
) -> InterRaterAgreementReport | None:
    """None unless 2+ annotators both have at least one shared, validly-scored
    case_id for this dimension -- never fabricates an agreement statistic from
    insufficient overlap."""
    from sklearn.metrics import cohen_kappa_score

    annotator_ids = sorted(per_annotator)
    if len(annotator_ids) < 2:
        return None

    # Pairwise comparison across the first two annotators supplied -- this
    # infrastructure supports exactly the case the task asked for (a second
    # annotator becoming available); more than two would need a multi-rater
    # agreement statistic (e.g. Fleiss' kappa), deliberately out of scope here.
    a_id, b_id = annotator_ids[0], annotator_ids[1]
    a_scores = per_annotator[a_id]
    b_scores = per_annotator[b_id]
    shared_case_ids = sorted(
        case_id
        for case_id in set(a_scores) & set(b_scores)
        if a_scores[case_id].status == "valid" and b_scores[case_id].status == "valid"
    )
    if not shared_case_ids:
        return None

    a_values = [a_scores[cid].value for cid in shared_case_ids]
    b_values = [b_scores[cid].value for cid in shared_case_ids]
    exact_agreement = sum(1 for a, b in zip(a_values, b_values) if a == b) / len(shared_case_ids)

    # cohen_kappa_score can return NaN (not raise) in a real, reproducible degenerate
    # case: both annotators gave the SAME CONSTANT score on every compared case (zero
    # variance in both raters), which makes kappa's "agreement beyond chance"
    # correction divide by zero internally (sklearn emits a RuntimeWarning for this,
    # not an exception -- verified during the Phase 18.1 audit). A NaN here would
    # otherwise sit silently in a `float` field; caught explicitly and reported as
    # None (undefined), never as a fabricated number, with the well-defined
    # percent_exact_agreement (1.0 in this exact case) still reported.
    with warnings.catch_warnings():
        warnings.filterwarnings("ignore", message="invalid value encountered in scalar divide", category=RuntimeWarning)
        raw_kappa = float(cohen_kappa_score(a_values, b_values, weights="linear", labels=[0, 1, 2]))
    kappa = None if math.isnan(raw_kappa) else round(raw_kappa, 6)

    note = (
        f"Descriptive only -- {len(shared_case_ids)} shared, validly-scored on-topic "
        "cases does not justify a significance test on kappa itself, and none is "
        "computed. Linear-weighted Cohen's kappa (sklearn.metrics.cohen_kappa_score) "
        "is used because the 0/1/2 scale is ordinal -- a 0-vs-2 disagreement is "
        "weighted as more severe than a 0-vs-1 disagreement, unlike unweighted kappa."
    )
    if kappa is None:
        note += (
            " cohens_weighted_kappa is UNDEFINED (not 0, not 1) here because both "
            "annotators gave the identical constant score on every compared case -- "
            "zero variance in both raters means there is no disagreement for kappa's "
            "chance-correction to be computed against. percent_exact_agreement (1.0) "
            "is the correct statistic to read in this specific case."
        )

    return InterRaterAgreementReport(
        annotator_ids=[a_id, b_id],
        dimension=name,
        cases_compared=len(shared_case_ids),
        percent_exact_agreement=round(exact_agreement, 6),
        cohens_weighted_kappa=kappa,
        note=note,
    )


def score_annotations(
    annotator_csv_paths: list[tuple[str, Path]],
    *,
    cases: list[tuple[str, str | None]] | None = None,
) -> LLMRubricAnnotationSummary:
    """`annotator_csv_paths`: a list of (annotator_id, csv_path) pairs -- one entry
    for a single annotator, two (or more) once a second annotator's filled CSV
    exists. cases defaults to llm_evaluation.py's DEFAULT_CASES (the same 7 cases
    the rubric template was generated from), so case_id/category alignment is
    always against the real, already-evaluated case set -- never invented."""
    if not annotator_csv_paths:
        raise RubricAnnotationError("At least one annotator CSV path is required.")

    cases = cases if cases is not None else DEFAULT_CASES
    annotator_ids = [annotator_id for annotator_id, _path in annotator_csv_paths]
    if len(annotator_ids) != len(set(annotator_ids)):
        raise RubricAnnotationError(f"Duplicate annotator_id in {annotator_ids!r} -- each annotator needs a distinct id.")

    negative_control_ids = {i for i, (_, category) in enumerate(cases) if category is None}
    on_topic_case_count = len(cases) - len(negative_control_ids)

    # per_dimension_by_annotator[dimension_name][annotator_id] = {case_id: RubricCaseScore}
    per_dimension_by_annotator: dict[str, dict[str, dict[int, RubricCaseScore]]] = {
        name: {} for name, _ in RUBRIC_DIMENSIONS
    }
    excluded_rows: list[str] = []

    for annotator_id, csv_path in annotator_csv_paths:
        per_dimension, excluded = parse_annotation_csv(csv_path, annotator_id=annotator_id, cases=cases)
        excluded_rows.extend(excluded)
        for name, scores_by_case in per_dimension.items():
            per_dimension_by_annotator[name][annotator_id] = scores_by_case

    dimensions: list[LLMRubricDimension] = []
    inter_rater: list[InterRaterAgreementReport] = []

    for name, description in RUBRIC_DIMENSIONS:
        per_annotator = per_dimension_by_annotator[name]
        # Pooled across all annotators -- each annotator-case pair counted once.
        # This is a plain pooled mean, not a reconciliation of disagreement; inter_rater
        # (below) is the separate, correct place to see whether annotators agreed.
        all_scores: list[RubricCaseScore] = [
            score for scores_by_case in per_annotator.values() for score in scores_by_case.values()
        ]
        valid = [s for s in all_scores if s.status == "valid"]
        invalid = [s for s in all_scores if s.status == "invalid"]
        unscored = [s for s in all_scores if s.status == "unscored"]
        mean_score = round(sum(s.value for s in valid) / len(valid), 6) if valid else None

        # "annotated"/"partially_annotated" reflect whether every ON-TOPIC CASE has
        # at least one annotator's valid score -- not every annotator x case pair,
        # so a single complete annotator alone can reach "annotated".
        cases_with_a_valid_score = {s.case_id for s in valid}
        status = _dimension_status(len(cases_with_a_valid_score), on_topic_case_count)

        dimensions.append(
            LLMRubricDimension(
                name=name,
                description=description,
                scale_description=SCALE_DESCRIPTION,
                status=status,
                mean_score=mean_score,
                scores=all_scores,
                valid_count=len(valid),
                invalid_count=len(invalid),
                unscored_count=len(unscored),
                on_topic_case_count=on_topic_case_count,
            )
        )

        agreement = _inter_rater_for_dimension(name, per_annotator)
        if agreement is not None:
            inter_rater.append(agreement)

    single_annotator_note = None
    if len(annotator_ids) == 1:
        single_annotator_note = (
            f"Single annotator ({annotator_ids[0]}). No inter-rater reliability statistic is computed or "
            "claimed -- that requires a second independent annotator's filled CSV (see this module's "
            "score_annotations(), which accepts additional (annotator_id, path) pairs). If this annotator is "
            "the thesis author, the resulting scores are author-produced and therefore NOT an independent "
            "quality judgment -- state this explicitly wherever these scores are reported, do not omit it."
        )

    return LLMRubricAnnotationSummary(
        annotator_ids=annotator_ids,
        on_topic_case_count=on_topic_case_count,
        negative_control_case_count=len(negative_control_ids),
        dimensions=dimensions,
        inter_rater=inter_rater or None,
        single_annotator_note=single_annotator_note,
        excluded_rows=excluded_rows,
        methodology_note=(
            f"Scored {len(annotator_ids)} annotator(s) ({', '.join(annotator_ids)}) against "
            f"{on_topic_case_count} on-topic cases (of {len(cases)} total; "
            f"{len(negative_control_ids)} negative-control cases are never scored on any "
            "dimension). A dimension's mean_score pools all annotators' valid scores; "
            "inter_rater (when 2+ annotators are present) separately reports whether "
            "those annotators actually agreed -- these are two distinct questions, never "
            "combined into one number. Blank cells are 'unscored' (excluded, never "
            "coerced to 0); non-0/1/2 cells are 'invalid' (excluded, reported in "
            "excluded_rows with the original text). This is human-annotation "
            "infrastructure only -- it never scores anything itself, and never uses an "
            "LLM as a judge."
        ),
    )


def render_rubric_summary_table(summary: LLMRubricAnnotationSummary) -> str:
    """Thesis-ready Markdown table, generated FROM the summary object -- never
    hand-typed. Kept as a standalone renderer (not folded into
    backend/evaluation/thesis_tables.py's EvaluationReport-shaped renderer) so the
    human-dependent artifact this reads never gets silently entangled with the
    fully-automated evaluation report."""
    lines = [
        "# LLM Rubric Human Annotation Summary\n",
        f"Annotators: {', '.join(summary.annotator_ids)}  |  On-topic cases: {summary.on_topic_case_count}  |  "
        f"Negative-control cases (never scored): {summary.negative_control_case_count}\n",
        "| Dimension | Status | Mean score | Valid | Invalid | Unscored |",
        "|---|---|---|---|---|---|",
    ]
    for dim in summary.dimensions:
        mean_text = f"{dim.mean_score:.4f}" if dim.mean_score is not None else "IMPLEMENTED / NOT YET MEASURED"
        lines.append(f"| {dim.name} | {dim.status} | {mean_text} | {dim.valid_count} | {dim.invalid_count} | {dim.unscored_count} |")

    if summary.inter_rater:
        lines.append("\n## Inter-rater agreement\n")
        lines += ["| Dimension | Annotators | Cases compared | % exact agreement | Cohen's weighted kappa |", "|---|---|---|---|---|"]
        for agreement in summary.inter_rater:
            kappa_text = f"{agreement.cohens_weighted_kappa:.4f}" if agreement.cohens_weighted_kappa is not None else "UNDEFINED (both raters gave a constant score -- see note)"
            lines.append(
                f"| {agreement.dimension} | {' vs '.join(agreement.annotator_ids)} | {agreement.cases_compared} | "
                f"{agreement.percent_exact_agreement:.4f} | {kappa_text} |"
            )
    elif summary.single_annotator_note:
        lines.append(f"\n**Inter-rater agreement:** not computed -- {summary.single_annotator_note}")

    if summary.excluded_rows:
        lines.append(f"\n## Excluded rows ({len(summary.excluded_rows)})\n")
        lines += [f"- {row}" for row in summary.excluded_rows]

    lines.append(f"\n{summary.methodology_note}")
    return "\n".join(lines) + "\n"


if __name__ == "__main__":
    import json
    import argparse

    parser = argparse.ArgumentParser(
        description="Phase 18 (P0.2): score human-filled LLM rubric annotation CSV(s). Infrastructure only -- never uses an LLM as a judge."
    )
    parser.add_argument("csv_files", nargs="+", type=Path, help="One filled annotation CSV per annotator.")
    parser.add_argument("--output", type=Path, default=DEFAULT_SUMMARY_OUTPUT_PATH, help=f"Where to write the JSON summary (default: {DEFAULT_SUMMARY_OUTPUT_PATH}).")
    args = parser.parse_args()

    output_path = args.output
    csv_paths = [(path.stem, path) for path in args.csv_files]
    result = score_annotations(csv_paths)

    output_path.parent.mkdir(parents=True, exist_ok=True)
    output_path.write_text(json.dumps(result.model_dump(), indent=2, default=str), encoding="utf-8")

    table_path = output_path.with_suffix(".md")
    table_path.write_text(render_rubric_summary_table(result), encoding="utf-8")

    print(render_rubric_summary_table(result))
    print(f"Wrote {output_path} and {table_path}")
