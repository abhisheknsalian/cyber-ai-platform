"""LLM analysis quality evaluation (Phase 16, Part E).

Scope, grounded in the actual architecture (not assumed): in this codebase, most of a
ThreatAnalysis is NOT LLM-generated. `threat` is the vector search's own top hit;
`mitre_attack` is parsed deterministically from source .txt files; `indicators`/
`mitigations` are deterministically derived from the threat graph whenever it has them
(which it does for every threat this knowledge base produces) and only fall back to
the LLM's own fragment otherwise (see backend/services/threat_analysis.py::analyze_query()).
The genuinely LLM-authored surface is: `severity`, `summary`, `attack_vectors`, and the
insufficient_context relevance decision. This module evaluates exactly that surface --
scoring indicators/mitigations/mitre_attack as "LLM quality" would misattribute a
backend-computed, already-correct-by-construction value to the model.

Automated dimensions (objective, computed here): schema validity, and whether the
model correctly recognizes an answerable vs. off-topic query. Everything else that
requires judging whether free-text output is actually GOOD (not just present) is a
rubric dimension: implemented as a template this module writes out for a human
annotator to fill in, never a fabricated score. See write_rubric_template().

Calls backend/services/threat_analysis.py::analyze_query() exactly as POST /analyze
already does -- no change to production LLM invocation, prompting, or parsing.

Phase 18 (P0.2): the rubric template written by write_rubric_template() now also
carries `retrieved_context_excerpt` (the same evidence text the LLM's summary/
attack_vectors were expected to be grounded in, re-fetched via
backend/evaluation/grounding.py::retrieved_context_text() -- no new retrieval logic)
and `is_negative_control` (True for the 2 off-topic cases, which have no content to
judge and must never contribute to a rubric dimension's mean -- see
backend/evaluation/llm_rubric_scoring.py, the module that actually reads a human's
filled-in copy of this template). This module still only ever WRITES an empty
template; it never scores anything itself and never uses an LLM as a judge.
"""

from __future__ import annotations

import csv
from pathlib import Path

from backend.evaluation.retrieval_relevance import EVALUATION_QUERIES
from backend.evaluation.schemas import LLMAutomatedMetrics, LLMEvaluationReport, LLMRubricDimension
from backend.rag.retrieval import vector_store_available
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.threat_analysis import analyze_query

# One query per real category (not all 15 -- each real LLM call costs several
# seconds; see README "Evaluation & Benchmarking" for why this module's default case
# count is deliberately small) plus two off-topic negative controls.
_CATEGORIES_SEEN: set[str] = set()
DEFAULT_CASES: list[tuple[str, str | None]] = []
for _query, _category in EVALUATION_QUERIES:
    if _category not in _CATEGORIES_SEEN:
        DEFAULT_CASES.append((_query, _category))
        _CATEGORIES_SEEN.add(_category)
DEFAULT_CASES.append(("What is the capital of France?", None))
DEFAULT_CASES.append(("Give me a recipe for chocolate chip cookies.", None))

RUBRIC_DIMENSIONS = [
    (
        "severity_reasonableness",
        "Is the assigned severity (Low/Medium/High/Critical) a reasonable judgment given the retrieved evidence?",
    ),
    (
        "summary_grounding_quality",
        "Does the summary genuinely reflect the retrieved threat-intelligence content, rather than generic or invented claims?",
    ),
    (
        "attack_vectors_relevance",
        "Are the listed attack vectors genuinely relevant to and supported by this specific threat's evidence?",
    ),
]
SCALE_DESCRIPTION = "0 = incorrect, 1 = partially correct, 2 = correct"

DEFAULT_RUBRIC_TEMPLATE_PATH = Path("evaluation/llm_rubric_template.csv")


class LLMEvaluationUnavailableError(RuntimeError):
    """Raised when a prerequisite (vector store, reachable Ollama) is missing --
    never fabricates LLM evaluation results."""


def score_column_name(dimension_name: str) -> str:
    """The exact CSV column header write_rubric_template() uses for a given rubric
    dimension's score -- a single source of truth so
    backend/evaluation/llm_rubric_scoring.py (which READS a filled-in copy of this
    template) can never silently drift from what this module WRITES."""
    return f"{dimension_name}_score (0/1/2, leave blank until annotated)"


# Cap on the retrieved-context excerpt written into the rubric template -- purely a
# defensive ceiling (this project's real threat-intel documents are all under 1KB,
# see data/threat_intel/*.txt, so this is not expected to ever truncate anything;
# it exists so a future, larger knowledge base can't silently produce an
# unreadable multi-page CSV cell).
_CONTEXT_EXCERPT_MAX_CHARS = 2000


def write_rubric_template(rows: list[dict], output_path: Path = DEFAULT_RUBRIC_TEMPLATE_PATH) -> Path:
    """Writes a CSV with one row per evaluated case -- query, category, the LLM's
    generated output, the retrieved evidence it was expected to use, whether the
    case is a negative (off-topic) control, and one empty score column per rubric
    dimension -- for a human annotator to fill in. This is the "implement the
    framework, document the required annotation process" path required when human
    judgment is genuinely needed and unavailable -- never a substitute for actually
    collecting the annotation. Never mutates the LLM's own output fields; the
    retrieved-context column is additional context, not a replacement value.

    `rows` is expected to already carry `retrieved_context_excerpt` and
    `is_negative_control` (see run_llm_evaluation()) -- kept as a plain
    list[dict] parameter (not typed to a specific case model) so this function
    stays independently testable with hand-built rows, matching the existing
    Phase 16 convention."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = [
        "case_id", "query", "category", "severity", "summary", "attack_vectors",
        "retrieved_context_excerpt", "is_negative_control",
    ] + [score_column_name(name) for name, _ in RUBRIC_DIMENSIONS]
    with output_path.open("w", newline="", encoding="utf-8") as handle:
        writer = csv.DictWriter(handle, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(row)
    return output_path


def run_llm_evaluation(
    cases: list[tuple[str, str | None]] | None = None,
    *,
    rubric_template_path: Path | None = DEFAULT_RUBRIC_TEMPLATE_PATH,
) -> LLMEvaluationReport:
    if not vector_store_available():
        raise LLMEvaluationUnavailableError(
            "Vector store not found. Build it first with: uv run python -m backend.rag.ingestion"
        )

    cases = cases if cases is not None else DEFAULT_CASES

    # Local import: grounding.py itself imports DEFAULT_CASES from this module at
    # module level, so a module-level import here would be circular. Reused, not
    # reimplemented -- the exact same context-fetch helper grounding.py's own
    # checks call to re-fetch the evidence text a case's output was expected to be
    # grounded in.
    from backend.evaluation.grounding import retrieved_context_text

    schema_valid = 0
    on_topic_total = 0
    on_topic_correct = 0
    off_topic_total = 0
    off_topic_correct = 0
    analyzed_total = 0
    analyzed_with_attack_vectors = 0
    analyzed_with_severity = 0
    template_rows: list[dict] = []

    for index, (query, expected_category) in enumerate(cases):
        try:
            result = analyze_query(query)
        except (LLMUnavailableError, LLMResponseError):
            continue  # not schema-valid; excluded from the schema_valid_rate numerator only
        schema_valid += 1

        is_analyzed = result.status == "analyzed"
        if expected_category is not None:
            on_topic_total += 1
            if is_analyzed:
                on_topic_correct += 1
        else:
            off_topic_total += 1
            if not is_analyzed:
                off_topic_correct += 1

        if is_analyzed:
            analyzed_total += 1
            if result.attack_vectors:
                analyzed_with_attack_vectors += 1
            if result.severity is not None:
                analyzed_with_severity += 1

        is_negative_control = expected_category is None
        if is_analyzed:
            context_excerpt = retrieved_context_text(query, result.threat)[:_CONTEXT_EXCERPT_MAX_CHARS]
        elif is_negative_control:
            context_excerpt = "(no retrieved evidence -- off-topic query correctly returned no analysis)"
        else:
            context_excerpt = "(no analysis produced for this on-topic case -- see automated status field)"

        template_rows.append(
            {
                "case_id": index,
                "query": query,
                "category": expected_category or "(negative control)",
                "severity": result.severity or "",
                "summary": result.summary,
                "attack_vectors": "; ".join(result.attack_vectors),
                "retrieved_context_excerpt": context_excerpt,
                "is_negative_control": is_negative_control,
            }
        )

    written_path = None
    if rubric_template_path is not None and template_rows:
        written_path = write_rubric_template(template_rows, rubric_template_path)

    automated = LLMAutomatedMetrics(
        cases_evaluated=len(cases),
        schema_valid_rate=round(schema_valid / len(cases), 6) if cases else 0.0,
        correct_relevance_on_topic_rate=round(on_topic_correct / on_topic_total, 6) if on_topic_total else None,
        correct_relevance_off_topic_rate=round(off_topic_correct / off_topic_total, 6) if off_topic_total else None,
        non_empty_attack_vectors_rate=round(analyzed_with_attack_vectors / analyzed_total, 6) if analyzed_total else 0.0,
        severity_present_rate=round(analyzed_with_severity / analyzed_total, 6) if analyzed_total else 0.0,
    )

    rubric_dimensions = [
        LLMRubricDimension(
            name=name,
            description=description,
            scale_description=SCALE_DESCRIPTION,
            status="not_yet_annotated",
            mean_score=None,
            scores=[],
        )
        for name, description in RUBRIC_DIMENSIONS
    ]

    return LLMEvaluationReport(
        automated=automated,
        rubric_dimensions=rubric_dimensions,
        rubric_template_path=str(written_path) if written_path else None,
        methodology_note=(
            "Only genuinely LLM-authored fields (severity, summary, attack_vectors, "
            "the insufficient_context relevance decision) are evaluated here -- "
            "threat/mitre_attack/indicators/mitigations are deterministically "
            "derived from source documents and the threat graph in this "
            "architecture, not LLM-generated, and are not re-scored as an 'LLM "
            "quality' dimension. Rubric dimensions require human annotation and are "
            "NOT YET MEASURED -- scores stay empty until a human fills in the "
            "written CSV template; mean_score is None until then. Never fabricated."
        ),
    )
