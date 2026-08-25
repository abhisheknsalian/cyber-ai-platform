"""CLI entry point: `uv run python -m backend.evaluation [--pipeline] [--output PATH]`.

Default (no flags) runs entirely offline: ML evaluation needs only the local dataset
CSV and the trained model artifact; retrieval evaluation additionally needs the
Chroma vector store and threat graph already built (`uv run python -m
backend.rag.ingestion`) -- neither needs Ollama. Pass --pipeline to additionally run
the end-to-end pipeline benchmark, which does need a reachable Ollama server.

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
from backend.evaluation.ml_evaluation import (
    DatasetUnavailableError,
    calibration_report,
    evaluate_full_dataset,
    evaluate_held_out_test,
    load_dataset_summary,
    load_model_summary,
    threshold_analysis,
)
from backend.evaluation.retrieval_evaluation import RetrievalUnavailableError, run_retrieval_benchmark
from backend.evaluation.schemas import EvaluationReport

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


def _build_report(*, include_pipeline: bool) -> EvaluationReport:
    limitations = list(_FIXED_LIMITATIONS)
    report = EvaluationReport(generated_at=datetime.now(timezone.utc).isoformat(), dataset=None, model=None)

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

    if include_pipeline:
        try:
            report.pipeline = run_pipeline_benchmark()
        except PipelineUnavailableError as exc:
            limitations.append(f"Pipeline benchmark unavailable: {exc}")
    else:
        limitations.append("Pipeline benchmark skipped (pass --pipeline to run it; requires a reachable Ollama server).")

    report.limitations = limitations
    return report


def _print_summary(report: EvaluationReport) -> None:
    print(f"Evaluation report generated at {report.generated_at}\n")

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

    if report.pipeline:
        print(f"\nPipeline benchmark ({report.pipeline.queries_evaluated} queries):")
        for stage in report.pipeline.stages:
            print(f"  {stage.stage}: mean={stage.latency.mean_ms}ms p95={stage.latency.p95_ms}ms")

    if report.limitations:
        print("\nLimitations:")
        for item in report.limitations:
            print(f"  - {item}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Phase 11 evaluation and benchmarking CLI.")
    parser.add_argument("--pipeline", action="store_true", help="Also run the Ollama-dependent end-to-end pipeline benchmark.")
    parser.add_argument("--output", type=Path, default=DEFAULT_OUTPUT, help=f"Where to write the JSON report (default: {DEFAULT_OUTPUT}).")
    args = parser.parse_args()

    report = _build_report(include_pipeline=args.pipeline)

    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report.model_dump(), indent=2, default=str), encoding="utf-8")

    _print_summary(report)
    print(f"\nFull report written to {args.output}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
