"""CLI entry point: `uv run python -m backend.evaluation [flags] [--output PATH]`.

Default (no flags) runs entirely offline: ML evaluation needs only the local dataset
CSV and the trained model artifact; retrieval evaluation, retrieval-relevance (Recall/
Precision/HitRate/MRR@k, Phase 16), and the vector-vs-hybrid ablation (Phase 16)
additionally need the Chroma vector store and threat graph already built (`uv run
python -m backend.rag.ingestion`) -- none of the above need Ollama.

Optional flags, each independently opt-in because each costs real time and/or a real
Ollama server:
  --pipeline    end-to-end pipeline latency benchmark (needs Ollama).
  --llm         LLM analysis quality + grounding evaluation, Phase 16 Parts E/F
                (needs Ollama).
  --leakage     Phase 17 RQ1: data-leakage audit + generalization experiment
                (offline, no Ollama, but trains several research-only RandomForest
                models -- takes roughly a minute).
  --reliability Phase 17 RQ5: repeated real end-to-end pipeline runs, tracking
                success/failure rate (needs Ollama, several real LLM calls).
  --ablation    Phase 17 RQ6/RQ3: component ablation + hybrid downstream-usefulness
                comparison (needs Ollama, several real LLM calls).
  --full        shorthand for all of the above.

Every section of the report is independently optional: if a prerequisite is missing
(no dataset, no model, no vector store, no Ollama), that section is omitted and a
plain-English reason is added to the report's limitations list -- never silently
skipped, never fabricated.
"""

from __future__ import annotations

import argparse
import json
import sys
from datetime import datetime, timezone
from pathlib import Path

from backend.evaluation.benchmark import PipelineUnavailableError, run_pipeline_benchmark
from backend.evaluation.component_ablation import ComponentAblationUnavailableError, run_component_ablation
from backend.evaluation.environment import capture_environment_info
from backend.evaluation.generalization_experiment import (
    GeneralizationExperimentUnavailableError,
    run_generalization_experiment,
)
from backend.evaluation.grounding import GroundingEvaluationUnavailableError, run_grounding_evaluation
from backend.evaluation.hybrid_ablation import HybridAblationUnavailableError, run_hybrid_ablation
from backend.evaluation.hybrid_downstream import DownstreamUsefulnessUnavailableError, run_downstream_usefulness
from backend.evaluation.leakage_audit import LeakageAuditUnavailableError, run_leakage_audit
from backend.evaluation.llm_evaluation import LLMEvaluationUnavailableError, run_llm_evaluation
from backend.evaluation.ml_evaluation import (
    DatasetUnavailableError,
    calibration_report,
    evaluate_full_dataset,
    evaluate_held_out_test,
    load_dataset_summary,
    load_model_summary,
    threshold_analysis,
)
from backend.evaluation.reliability import ReliabilityUnavailableError, run_reliability_experiment
from backend.evaluation.retrieval_evaluation import RetrievalUnavailableError, run_retrieval_benchmark
from backend.evaluation.retrieval_relevance import RelevanceEvaluationUnavailableError, run_retrieval_relevance_evaluation
from backend.evaluation.schemas import EvaluationReport
from backend.evaluation.thesis_tables import render_markdown_tables

DEFAULT_OUTPUT = Path("evaluation/latest.json")

_FIXED_LIMITATIONS = [
    "The local dataset contains only BENIGN and DDoS traffic (CICIDS2017 Friday "
    "afternoon DDoS capture). All classification metrics -- including the ~99.99% "
    "accuracy figures -- describe binary DDoS-vs-benign separability on THIS dataset "
    "only, and must not be read as general-purpose or universal DDoS-detection "
    "performance, nor as evidence about performance on any attack type not "
    "represented in this data (port scans, botnets, web attacks, brute force, "
    "infiltration, etc.). See README 'Evaluation & Benchmarking' for what additional "
    "labeled data would be required for a genuine multi-class benchmark.",
    "'held_out_test' classification metrics are a true generalization estimate "
    "(reconstructed test split, rows never used to fit the model). 'full_dataset' "
    "metrics are descriptive only -- most of those rows were used in training -- and "
    "are intentionally kept separate so one is never mistaken for the other.",
    "Threshold and calibration analysis are evaluation-only: they identify a "
    "best-F1 threshold and measure calibration quality, but do not change the "
    "production classifier's decision boundary (argmax over class_probabilities).",
    "Retrieval evaluation reports topic-coverage and evidence-preservation rates "
    "against a small, pre-established 5-topic query set, not a formal retrieval "
    "accuracy/precision@k benchmark -- this repository has no independently-labeled "
    "relevance judgment set to compute that against.",
]


def _build_report(
    *,
    include_pipeline: bool,
    include_llm: bool = False,
    include_leakage: bool = False,
    include_reliability: bool = False,
    include_ablation: bool = False,
) -> EvaluationReport:
    limitations = list(_FIXED_LIMITATIONS)
    report = EvaluationReport(generated_at=datetime.now(timezone.utc).isoformat(), dataset=None, model=None)
    report.environment = capture_environment_info()

    try:
        report.dataset = load_dataset_summary()
    except DatasetUnavailableError as exc:
        limitations.append(f"Dataset summary unavailable: {exc}")

    try:
        report.model = load_model_summary()
    except DatasetUnavailableError as exc:
        limitations.append(f"Model summary unavailable: {exc}")

    if report.dataset is not None and report.model is not None:
        held_out_metrics, cross_check = evaluate_held_out_test()
        report.classification["held_out_test"] = held_out_metrics
        report.classification["full_dataset"] = evaluate_full_dataset()
        report.threshold_analysis = threshold_analysis()
        report.calibration = calibration_report()
        if not cross_check.get("matches_recorded_test_rows", True):
            limitations.append(
                "Held-out split reconstruction did NOT match metadata.json's recorded "
                f"test_rows ({cross_check}); treat held_out_test metrics with caution."
            )

    try:
        report.retrieval = run_retrieval_benchmark()
    except RetrievalUnavailableError as exc:
        limitations.append(f"Retrieval benchmark unavailable: {exc}")

    try:
        report.retrieval_relevance = run_retrieval_relevance_evaluation()
    except RelevanceEvaluationUnavailableError as exc:
        limitations.append(f"Retrieval relevance (Recall/Precision/MRR@k) evaluation unavailable: {exc}")

    try:
        report.hybrid_ablation = run_hybrid_ablation()
    except HybridAblationUnavailableError as exc:
        limitations.append(f"Vector-vs-hybrid ablation unavailable: {exc}")

    if include_pipeline:
        try:
            report.pipeline = run_pipeline_benchmark()
        except PipelineUnavailableError as exc:
            limitations.append(f"Pipeline benchmark unavailable: {exc}")
    else:
        limitations.append("Pipeline benchmark skipped (pass --pipeline to run it; requires a reachable Ollama server).")

    if include_llm:
        try:
            report.llm_evaluation = run_llm_evaluation()
        except LLMEvaluationUnavailableError as exc:
            limitations.append(f"LLM evaluation unavailable: {exc}")
        try:
            report.grounding = run_grounding_evaluation()
        except GroundingEvaluationUnavailableError as exc:
            limitations.append(f"Grounding evaluation unavailable: {exc}")
        if report.llm_evaluation is not None:
            limitations.append(
                "LLM evaluation's rubric dimensions (severity_reasonableness, "
                "summary_grounding_quality, attack_vectors_relevance) require human "
                "annotation and are NOT YET MEASURED -- see "
                f"{report.llm_evaluation.rubric_template_path}."
            )
        if report.grounding is not None:
            limitations.append(
                "Grounding evaluation's supported_ratio is a coarse lexical-overlap "
                "proxy, not fact verification -- see grounding.methodology_note."
            )
    else:
        limitations.append(
            "LLM evaluation and grounding checks skipped (pass --llm to run them; requires a reachable Ollama server)."
        )

    if include_leakage:
        try:
            report.leakage_audit = run_leakage_audit()
        except LeakageAuditUnavailableError as exc:
            limitations.append(f"Leakage audit unavailable: {exc}")
        try:
            report.generalization_experiment = run_generalization_experiment()
        except GeneralizationExperimentUnavailableError as exc:
            limitations.append(f"Generalization experiment unavailable: {exc}")
        if report.leakage_audit is not None:
            limitations.append(
                "Leakage audit: temporal/host-level/file-level splits are NOT "
                "MEASURABLE from the local CICIDS2017 CSV (no Timestamp/Source "
                "IP/Flow ID column, only one capture file) -- see "
                "leakage_audit.split_feasibility.reason."
            )
    else:
        limitations.append(
            "RQ1 leakage audit + generalization experiment skipped (pass --leakage "
            "to run them; offline, no Ollama needed, but trains several "
            "research-only models -- takes roughly a minute)."
        )

    if include_reliability:
        try:
            report.reliability = run_reliability_experiment()
        except ReliabilityUnavailableError as exc:
            limitations.append(f"Reliability experiment unavailable: {exc}")
    else:
        limitations.append(
            "RQ5 end-to-end reliability experiment skipped (pass --reliability to "
            "run it; requires a reachable Ollama server, several real LLM calls)."
        )

    if include_ablation:
        try:
            report.component_ablation = run_component_ablation()
        except ComponentAblationUnavailableError as exc:
            limitations.append(f"Component ablation unavailable: {exc}")
        try:
            report.downstream_usefulness = run_downstream_usefulness()
        except DownstreamUsefulnessUnavailableError as exc:
            limitations.append(f"Hybrid downstream-usefulness comparison unavailable: {exc}")
    else:
        limitations.append(
            "RQ6 component ablation + RQ3 hybrid downstream-usefulness comparison "
            "skipped (pass --ablation to run them; requires a reachable Ollama "
            "server, several real LLM calls)."
        )

    report.limitations = limitations
    return report


def _print_summary(report: EvaluationReport) -> None:
    print(f"Evaluation report generated at {report.generated_at}\n")

    if report.environment:
        env = report.environment
        print(
            f"Environment: {env.os} {env.os_version}, Python {env.python_version}, "
            f"Ollama CLI {env.ollama_cli_version or 'not found'}, model={env.ollama_model}, "
            f"seed={env.random_seed}\n"
        )

    if report.dataset:
        print(f"Dataset: {report.dataset.rows_after_cleaning} rows, classes={report.dataset.class_labels}")
        print(f"  class_distribution={report.dataset.class_distribution}")
    if report.model:
        print(f"Model: {report.model.model_path} (version={report.model.model_version})")

    held_out = report.classification.get("held_out_test")
    if held_out:
        print(
            f"\nHeld-out test ({held_out.samples} samples): "
            f"accuracy={held_out.accuracy:.6f} f1_macro={held_out.f1_macro:.6f} "
            f"roc_auc={held_out.roc_auc} pr_auc={held_out.pr_auc}"
        )
        print(f"  inference latency: mean={held_out.inference_latency_ms.mean_ms}ms p95={held_out.inference_latency_ms.p95_ms}ms")

    full = report.classification.get("full_dataset")
    if full:
        print(f"Full dataset (descriptive only, {full.samples} samples): accuracy={full.accuracy:.6f}")

    if report.threshold_analysis:
        ta = report.threshold_analysis
        print(f"\nThreshold analysis: best_f1={ta.best_f1} at threshold={ta.best_f1_threshold} (production stays at {ta.production_threshold})")

    if report.calibration:
        print(f"Calibration: brier_score={report.calibration.brier_score}")

    if report.retrieval:
        r = report.retrieval
        print(
            f"\nRetrieval ({r.queries_evaluated} queries): topic_coverage_rate={r.topic_coverage_rate} "
            f"hybrid_preserves_both_sources_rate={r.hybrid_preserves_both_sources_rate}"
        )
        print(f"  vector p95={r.vector_latency.p95_ms}ms  graph p95={r.graph_latency.p95_ms}ms  hybrid p95={r.hybrid_latency.p95_ms}ms")

    if report.retrieval_relevance:
        rr = report.retrieval_relevance
        print(f"\nRetrieval relevance ({rr.queries_evaluated} queries, k={rr.k_values}):")
        for row in rr.overall:
            print(f"  k={row.k}: recall={row.recall_at_k} precision={row.precision_at_k} hit_rate={row.hit_rate_at_k} mrr={row.mrr_at_k}")

    if report.hybrid_ablation:
        ha = report.hybrid_ablation
        print(
            f"\nHybrid ablation ({ha.queries_evaluated} queries): "
            f"evidence_coverage_rate={ha.evidence_coverage_rate} "
            f"mean_latency_overhead_ms={ha.mean_latency_overhead_ms}"
        )
        print(f"  relevance_delta (hybrid - vector_only): {[(d.k, d.recall_at_k) for d in ha.relevance_delta]}")

    if report.pipeline:
        print(f"\nPipeline benchmark ({report.pipeline.queries_evaluated} queries):")
        for stage in report.pipeline.stages:
            share = (report.pipeline.stage_latency_share_pct or {}).get(stage.stage)
            share_text = f" ({share}% of total)" if share is not None else ""
            print(f"  {stage.stage}: mean={stage.latency.mean_ms}ms p95={stage.latency.p95_ms}ms{share_text}")

    if report.llm_evaluation:
        le = report.llm_evaluation.automated
        print(
            f"\nLLM evaluation (automated, {le.cases_evaluated} cases): "
            f"schema_valid_rate={le.schema_valid_rate} "
            f"on_topic_correct={le.correct_relevance_on_topic_rate} "
            f"off_topic_correct={le.correct_relevance_off_topic_rate}"
        )
        print("  Rubric dimensions: NOT YET MEASURED (human annotation required) -- see", report.llm_evaluation.rubric_template_path)

    if report.grounding:
        print(
            f"\nGrounding ({report.grounding.cases_evaluated} cases): "
            f"lexical_proxy={report.grounding.mean_supported_ratio} "
            f"semantic_proxy={report.grounding.mean_supported_ratio_semantic}"
        )

    if report.leakage_audit:
        la = report.leakage_audit
        print(f"\nLeakage audit (RQ1): exact-dup rate before cleaning={la.exact_duplicates.duplicate_rate_before_cleaning}")
        print(f"  cross-label feature collisions: {la.cross_label_collisions.affected_rows} rows ({la.cross_label_collisions.affected_row_rate:.4%})")
        print(f"  near-duplicate 1-NN distance: median={la.near_duplicates.distance.median} fractions={la.near_duplicates.near_duplicate_fraction_by_threshold}")
        print(f"  family grouping: {la.family_grouping.fraction_rows_in_multi_row_families:.4%} of rows in multi-row families")

    if report.generalization_experiment:
        ge = report.generalization_experiment
        print(f"\nGeneralization experiment: baseline acc={ge.baseline.accuracy} vs family_grouped acc={ge.family_grouped.accuracy if ge.family_grouped else None}")
        print(f"  repeated random splits: mean={ge.repeated_random_splits.accuracy_mean} stddev={ge.repeated_random_splits.accuracy_stddev}")

    if report.reliability:
        rel = report.reliability
        print(f"\nReliability (RQ5, {rel.runs_attempted} runs): success_rate={rel.success_rate} failure_rate={rel.failure_rate}")
        if rel.total_latency:
            print(f"  total latency: mean={rel.total_latency.mean}ms stddev={rel.total_latency.stddev}ms p95={rel.total_latency.p95}ms")

    if report.component_ablation:
        print("\nComponent ablation (RQ6):")
        for c in report.component_ablation.conditions:
            print(f"  {c.condition}: latency_mean={c.latency.mean}ms evidence={c.evidence_chunk_count_mean} schema_valid={c.schema_valid_rate} grounding={c.grounding_supported_ratio_mean}")

    if report.downstream_usefulness:
        du = report.downstream_usefulness
        print(f"\nDownstream usefulness of graph evidence (RQ3, {du.cases_evaluated} cases): severity_changed_rate={du.severity_changed_rate} mitigations_gained_rate={du.mitigations_gained_with_graph_rate}")

    if report.limitations:
        print("\nLimitations:")
        for item in report.limitations:
            print(f"  - {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 11/16/17 evaluation and benchmarking CLI.")
    parser.add_argument("--pipeline", action="store_true", help="Also run the Ollama-dependent end-to-end pipeline latency benchmark.")
    parser.add_argument(
        "--llm",
        action="store_true",
        help="Also run the Ollama-dependent LLM analysis quality + grounding evaluation (Phase 16, Parts E/F).",
    )
    parser.add_argument(
        "--leakage",
        action="store_true",
        help="Also run the Phase 17 RQ1 data-leakage audit + generalization experiment (offline, ~1 minute).",
    )
    parser.add_argument(
        "--reliability",
        action="store_true",
        help="Also run the Phase 17 RQ5 end-to-end reliability experiment (needs Ollama, several real LLM calls).",
    )
    parser.add_argument(
        "--ablation",
        action="store_true",
        help="Also run the Phase 17 RQ6/RQ3 component ablation + hybrid downstream-usefulness comparison (needs Ollama).",
    )
    parser.add_argument("--full", action="store_true", help="Shorthand for --pipeline --llm --leakage --reliability --ablation.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"Where to write the JSON report (default: {DEFAULT_OUTPUT}).")
    args = parser.parse_args()

    report = _build_report(
        include_pipeline=args.pipeline or args.full,
        include_llm=args.llm or args.full,
        include_leakage=args.leakage or args.full,
        include_reliability=args.reliability or args.full,
        include_ablation=args.ablation or args.full,
    )

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.model_dump(), indent=2, default=str), encoding="utf-8")

    tables_path = args.output.with_name("thesis_tables.md")
    tables_path.write_text(render_markdown_tables(report), encoding="utf-8")

    _print_summary(report)
    print(f"\nFull report written to {args.output}")
    print(f"Thesis tables written to {tables_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
