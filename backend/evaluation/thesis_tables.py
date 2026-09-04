"""Renders the thesis-ready Markdown tables (Phase 17) FROM an already-produced
EvaluationReport -- never hardcodes a number. Every value in the output is read from
the report object; a section with no data renders "NOT MEASURED" rather than being
silently omitted or backfilled with a placeholder number.

Usage: called by backend/evaluation/__main__.py after building the report; also
callable directly against a saved JSON file (see __main__ block below) for
regenerating tables without re-running any experiment.
"""

from __future__ import annotations

from backend.evaluation.schemas import EvaluationReport

_NOT_MEASURED = "_NOT MEASURED_"


def _fmt(value, digits: int = 4) -> str:
    if value is None:
        return _NOT_MEASURED
    if isinstance(value, float):
        return f"{value:.{digits}f}"
    return str(value)


def _table_1_ml_performance(report: EvaluationReport) -> str:
    lines = ["## Table 1: ML Classification Performance\n", "| Split | Samples | Accuracy | Precision (macro) | Recall (macro) | F1 (macro) | ROC-AUC | PR-AUC |", "|---|---|---|---|---|---|---|---|"]
    for name, metrics in report.classification.items():
        # 6 digits, not the default 4 -- at 4 digits this dataset's near-perfect
        # scores (e.g. 0.999982) visually round to a misleading "1.0000".
        lines.append(
            f"| {name} | {metrics.samples} | {_fmt(metrics.accuracy, 6)} | {_fmt(metrics.precision_macro, 6)} | "
            f"{_fmt(metrics.recall_macro, 6)} | {_fmt(metrics.f1_macro, 6)} | {_fmt(metrics.roc_auc, 6)} | {_fmt(metrics.pr_auc, 6)} |"
        )
    if not report.classification:
        lines.append(f"| {_NOT_MEASURED} | | | | | | | |")
    if "held_out_test" in report.classification and report.classification["held_out_test"].accuracy_ci:
        ci = report.classification["held_out_test"].accuracy_ci
        lines.append(f"\nHeld-out accuracy {ci.confidence_level:.0%} Wilson CI: [{_fmt(ci.lower)}, {_fmt(ci.upper)}]")
    return "\n".join(lines)


def _table_2_leakage_generalization(report: EvaluationReport) -> str:
    lines = ["## Table 2: Leakage / Generalization Comparison\n"]
    if report.leakage_audit is None:
        lines.append(_NOT_MEASURED + " (run with --leakage)")
        return "\n".join(lines)

    la = report.leakage_audit
    lines += [
        "| Check | Result |",
        "|---|---|",
        f"| Exact-duplicate rate (raw, before cleaning) | {_fmt(la.exact_duplicates.duplicate_rate_before_cleaning, 6)} |",
        f"| Cross-label feature-vector collisions (rows) | {la.cross_label_collisions.affected_rows} ({_fmt(la.cross_label_collisions.affected_row_rate, 6)}) |",
        f"| Near-duplicate test rows (standardized 1-NN dist < 0.01) | {_fmt(la.near_duplicates.near_duplicate_fraction_by_threshold.get('euclidean_lt_0.01'), 4)} |",
        f"| Near-duplicate test rows (dist < 0.1) | {_fmt(la.near_duplicates.near_duplicate_fraction_by_threshold.get('euclidean_lt_0.1'), 4)} |",
        f"| Rows in a multi-row rounding-based family | {_fmt(la.family_grouping.fraction_rows_in_multi_row_families, 4)} |",
        f"| Temporal split possible | {la.split_feasibility.temporal_split_possible} |",
        f"| Host-level split possible | {la.split_feasibility.host_split_possible} |",
    ]

    ge = report.generalization_experiment
    if ge is not None:
        lines += [
            "",
            "| Split | Production artifact? | Test rows | Accuracy | F1 (macro) |",
            "|---|---|---|---|---|",
            f"| {ge.baseline.split_name} | Yes | {ge.baseline.test_rows} | {_fmt(ge.baseline.accuracy, 6)} | {_fmt(ge.baseline.f1_macro, 6)} |",
        ]
        if ge.family_grouped:
            lines.append(
                f"| {ge.family_grouped.split_name} | No (research-only) | {ge.family_grouped.test_rows} | "
                f"{_fmt(ge.family_grouped.accuracy, 6)} | {_fmt(ge.family_grouped.f1_macro, 6)} |"
            )
        rv = ge.repeated_random_splits
        lines.append(
            f"\nRepeated random splits ({len(rv.seeds)} seeds): accuracy mean={_fmt(rv.accuracy_mean, 6)}, "
            f"stddev={_fmt(rv.accuracy_stddev, 6)}"
        )
    else:
        lines.append(f"\nGeneralization experiment: {_NOT_MEASURED}")
    return "\n".join(lines)


def _table_3_retrieval(report: EvaluationReport) -> str:
    lines = ["## Table 3: Retrieval Performance (per k)\n"]
    if report.retrieval_relevance is None:
        lines.append(_NOT_MEASURED)
        return "\n".join(lines)
    rr = report.retrieval_relevance
    lines += ["| k | Recall@k | Precision@k | HitRate@k | MRR@k |", "|---|---|---|---|---|"]
    for row in rr.overall:
        lines.append(f"| {row.k} | {_fmt(row.recall_at_k)} | {_fmt(row.precision_at_k)} | {_fmt(row.hit_rate_at_k)} | {_fmt(row.mrr_at_k)} |")
    lines.append("\n### Per category (k=5)\n")
    lines += ["| Category | Queries | Recall@5 | Precision@5 |", "|---|---|---|---|"]
    for cat in rr.categories:
        row5 = next((m for m in cat.metrics if m.k == 5), None)
        lines.append(f"| {cat.category} | {cat.query_count} | {_fmt(row5.recall_at_k) if row5 else _NOT_MEASURED} | {_fmt(row5.precision_at_k) if row5 else _NOT_MEASURED} |")
    if rr.recall_at_5_ci:
        lines.append(f"\nRecall@5 bootstrap {rr.recall_at_5_ci.confidence_level:.0%} CI: [{_fmt(rr.recall_at_5_ci.lower)}, {_fmt(rr.recall_at_5_ci.upper)}] (n={rr.queries_evaluated})")
    return "\n".join(lines)


def _table_4_vector_vs_hybrid(report: EvaluationReport) -> str:
    lines = ["## Table 4: Vector-only vs. Hybrid Retrieval\n"]
    if report.hybrid_ablation is None:
        lines.append(_NOT_MEASURED)
        return "\n".join(lines)
    ha = report.hybrid_ablation
    lines += ["| k | Recall delta | Precision delta | HitRate delta | MRR delta |", "|---|---|---|---|---|"]
    for row in ha.relevance_delta:
        lines.append(f"| {row.k} | {_fmt(row.recall_at_k)} | {_fmt(row.precision_at_k)} | {_fmt(row.hit_rate_at_k)} | {_fmt(row.mrr_at_k)} |")
    lines.append(
        f"\nEvidence coverage rate: {_fmt(ha.evidence_coverage_rate)}  |  "
        f"Mean graph entities/query: {_fmt(ha.mean_graph_entity_count)}  |  "
        f"Mean graph relationships/query: {_fmt(ha.mean_graph_relationship_count)}  |  "
        f"Mean latency overhead: {_fmt(ha.mean_latency_overhead_ms, 4)} ms"
    )
    du = report.downstream_usefulness
    if du is not None:
        lines.append(
            f"\n**Downstream LLM-analysis usefulness of graph evidence** ({du.cases_evaluated} cases): "
            f"severity changed in {_fmt(du.severity_changed_rate)} of cases, attack_vectors changed in "
            f"{_fmt(du.attack_vectors_changed_rate)}, mitigations gained in {_fmt(du.mitigations_gained_with_graph_rate)}."
        )
    else:
        lines.append(f"\nDownstream usefulness: {_NOT_MEASURED} (run with --ablation)")
    return "\n".join(lines)


def _table_5_llm(report: EvaluationReport) -> str:
    lines = ["## Table 5: LLM Evaluation\n"]
    if report.llm_evaluation is None:
        lines.append(_NOT_MEASURED)
        return "\n".join(lines)
    le = report.llm_evaluation
    a = le.automated
    lines += [
        "| Automated metric | Value |",
        "|---|---|",
        f"| Cases evaluated | {a.cases_evaluated} |",
        f"| Schema-valid rate | {_fmt(a.schema_valid_rate)} |",
        f"| Correct relevance (on-topic) | {_fmt(a.correct_relevance_on_topic_rate)} |",
        f"| Correct relevance (off-topic) | {_fmt(a.correct_relevance_off_topic_rate)} |",
        f"| Non-empty attack_vectors rate | {_fmt(a.non_empty_attack_vectors_rate)} |",
        f"| Severity present rate | {_fmt(a.severity_present_rate)} |",
        "",
        "| Human rubric dimension | Status | Mean score |",
        "|---|---|---|",
    ]
    for dim in le.rubric_dimensions:
        lines.append(f"| {dim.name} | {dim.status.upper()} | {_fmt(dim.mean_score) if dim.mean_score is not None else 'IMPLEMENTED / NOT YET MEASURED'} |")
    if le.rubric_template_path:
        lines.append(f"\nAnnotation template: `{le.rubric_template_path}`")

    if report.grounding is not None:
        g = report.grounding
        lines.append(
            f"\n**Grounding** ({g.cases_evaluated} cases): lexical proxy = {_fmt(g.mean_supported_ratio)}, "
            f"semantic proxy = {_fmt(g.mean_supported_ratio_semantic)}. Both are proxies, "
            "NOT hallucination detection -- see grounding.methodology_note in the JSON report."
        )
    else:
        lines.append(f"\nGrounding: {_NOT_MEASURED} (run with --llm)")
    return "\n".join(lines)


def _table_6_latency(report: EvaluationReport) -> str:
    lines = ["## Table 6: End-to-End Latency\n"]
    if report.pipeline is None and report.reliability is None:
        lines.append(_NOT_MEASURED)
        return "\n".join(lines)

    if report.pipeline:
        lines += ["| Stage | Mean (ms) | P95 (ms) | Stddev (ms) | % of total |", "|---|---|---|---|---|"]
        shares = report.pipeline.stage_latency_share_pct or {}
        for stage in report.pipeline.stages:
            lat = stage.latency
            share = shares.get(stage.stage)
            lines.append(f"| {stage.stage} | {_fmt(lat.mean_ms, 2)} | {_fmt(lat.p95_ms, 2)} | {_fmt(lat.stddev_ms, 2)} | {_fmt(share, 2) if share is not None else _NOT_MEASURED} |")
    else:
        lines.append(f"Pipeline stage breakdown: {_NOT_MEASURED} (run with --pipeline)")

    if report.reliability:
        rel = report.reliability
        lines.append(f"\n**Reliability** ({rel.runs_attempted} runs): success rate = {_fmt(rel.success_rate)}, failure rate = {_fmt(rel.failure_rate)}")
        if rel.total_latency:
            t = rel.total_latency
            lines.append(
                f"Total end-to-end latency: mean={_fmt(t.mean, 2)}ms, median={_fmt(t.median, 2)}ms, "
                f"stddev={_fmt(t.stddev, 2)}ms, p95={_fmt(t.p95, 2)}ms, min={_fmt(t.min, 2)}ms, max={_fmt(t.max, 2)}ms"
            )
    else:
        lines.append(f"\nReliability (repeated-run success/failure): {_NOT_MEASURED} (run with --reliability)")
    return "\n".join(lines)


def _table_7_ablation(report: EvaluationReport) -> str:
    lines = ["## Table 7: Component Ablation\n"]
    if report.component_ablation is None:
        lines.append(_NOT_MEASURED + " (run with --ablation)")
        return "\n".join(lines)
    lines += [
        "| Condition | Mean latency (ms) | Evidence chunks | Graph entities | Graph relationships | Schema valid | Grounding |",
        "|---|---|---|---|---|---|---|",
    ]
    for c in report.component_ablation.conditions:
        lines.append(
            f"| {c.condition} | {_fmt(c.latency.mean, 2)} | {_fmt(c.evidence_chunk_count_mean, 2) if c.evidence_chunk_count_mean is not None else '-'} | "
            f"{_fmt(c.graph_entity_count_mean, 2) if c.graph_entity_count_mean is not None else '-'} | "
            f"{_fmt(c.graph_relationship_count_mean, 2) if c.graph_relationship_count_mean is not None else '-'} | "
            f"{_fmt(c.schema_valid_rate) if c.schema_valid_rate is not None else '-'} | "
            f"{_fmt(c.grounding_supported_ratio_mean) if c.grounding_supported_ratio_mean is not None else '-'} |"
        )
    return "\n".join(lines)


def render_markdown_tables(report: EvaluationReport) -> str:
    sections = [
        f"# Thesis Evaluation Tables\n\nGenerated at {report.generated_at} from a real evaluation run "
        "(see evaluation/latest.json for the full machine-readable report this was rendered from). "
        "Every number below is read from that report -- nothing here is hand-typed.",
        _table_1_ml_performance(report),
        _table_2_leakage_generalization(report),
        _table_3_retrieval(report),
        _table_4_vector_vs_hybrid(report),
        _table_5_llm(report),
        _table_6_latency(report),
        _table_7_ablation(report),
    ]
    return "\n\n".join(sections) + "\n"


if __name__ == "__main__":
    import json
    import sys
    from pathlib import Path

    src = Path(sys.argv[1]) if len(sys.argv) > 1 else Path("evaluation/latest.json")
    dest = Path(sys.argv[2]) if len(sys.argv) > 2 else Path("evaluation/thesis_tables.md")
    report = EvaluationReport.model_validate(json.loads(src.read_text()))
    dest.write_text(render_markdown_tables(report), encoding="utf-8")
    print(f"Wrote {dest}")
