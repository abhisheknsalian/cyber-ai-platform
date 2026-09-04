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

_RUBRIC_DIMENSIONS = [
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
_SCALE_DESCRIPTION = "0 = incorrect, 1 = partially correct, 2 = correct"

DEFAULT_RUBRIC_TEMPLATE_PATH = Path("evaluation/llm_rubric_template.csv")


class LLMEvaluationUnavailableError(RuntimeError):
    """Raised when a prerequisite (vector store, reachable Ollama) is missing --
    never fabricates LLM evaluation results."""


def write_rubric_template(rows: list[dict], output_path: Path = DEFAULT_RUBRIC_TEMPLATE_PATH) -> Path:
    """Writes a CSV with one row per evaluated case and one empty score column per
    rubric dimension, for a human annotator to fill in. This is the "implement the
    framework, document the required annotation process" path required when human
    judgment is genuinely needed and unavailable -- never a substitute for actually
    collecting the annotation."""
    output_path.parent.mkdir(parents=True, exist_ok=True)
    fieldnames = ["case_id", "query", "category", "severity", "summary", "attack_vectors"] + [
        f"{name}_score (0/1/2, leave blank until annotated)" for name, _ in _RUBRIC_DIMENSIONS
    ]
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

        template_rows.append(
            {
                "case_id": index,
                "query": query,
                "category": expected_category or "(negative control)",
                "severity": result.severity or "",
                "summary": result.summary,
                "attack_vectors": "; ".join(result.attack_vectors),
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
            scale_description=_SCALE_DESCRIPTION,
            status="not_yet_annotated",
            mean_score=None,
            scores=[],
        )
        for name, description in _RUBRIC_DIMENSIONS
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
