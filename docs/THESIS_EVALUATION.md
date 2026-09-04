# Thesis-Grade Experimental Validation (Phase 17)

This document is the research-methodology companion to the product README's
[Evaluation & Benchmarking](../README.md#evaluation--benchmarking) section. That
section documents what the evaluation *tooling* is and how to run it; this document
answers the scientific question Phase 17 was scoped around: **are this system's
research claims defensible, and exactly how far do they extend?**

Every number quoted below comes from a real run of `uv run python -m backend.evaluation
--full` against the real local CICIDS2017 CSV, the real trained model artifact, the
real Chroma vector store, the real threat graph, and a real local Ollama server
(`llama3.2:3b`) — recorded in `evaluation/latest.json` (gitignored, regenerate with the
command above) and rendered as tables in `evaluation/thesis_tables.md`. Nothing here is
hand-typed or invented; where a number doesn't exist yet, it says so explicitly.

## 1. Research questions

- **RQ1** — How well does the supervised network classifier generalize to unseen
  network traffic?
- **RQ2** — How accurately does the threat-intelligence retrieval system retrieve
  relevant information?
- **RQ3** — Does hybrid vector + graph retrieval improve evidence quality compared
  with vector-only retrieval?
- **RQ4** — Does retrieval-grounded LLM analysis produce useful and sufficiently
  grounded threat assessments?
- **RQ5** — What are the latency and reliability characteristics of the complete
  pipeline?
- **RQ6** — What contribution does each major component make to the final system?

## 2. Experimental methodology (overview)

All Phase 17 code lives under `backend/evaluation/` alongside the Phase 11/16
evaluation layer it extends — a read-only measurement layer that calls existing
production functions (classifier `predict()`, `retrieve_relevant()`,
`gather_hybrid_evidence()`, `analyze_query()`) and never modifies their behavior, never
retrains the production model, and never alters `/classify`, `/analyze`,
`/analyze/classification`, retrieval, the graph, or the LLM prompt/parsing. Every
result section is independently optional on `EvaluationReport`: a missing prerequisite
degrades that section to absent plus a plain-English reason in `limitations`, never a
fabricated substitute value.

## 3. Dataset methodology

The real dataset is CICIDS2017's "Friday-WorkingHours-Afternoon-DDos" capture
(`data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, ~223k rows after
cleaning), the **"MachineLearningCSV" distribution variant**: 78 CICFlowMeter feature
columns plus `Label`, verified by reading the raw header. It carries **no Flow ID,
Source/Destination IP, Source Port, or Timestamp column** — a real, structural
property of the distributed data, not a limitation of this evaluation's code. This one
fact drives most of the leakage-audit design below (§4).

Preprocessing (`backend/ml/preprocessing.py`, unchanged by Phase 17): drop
infinite/NaN rows, then `drop_duplicates()` on the full cleaned frame (every feature
column + `Label` together) **before** the train/test split — verified structurally by
reading the code, and verified empirically by reconstructing the split and matching
the model's recorded metadata exactly (see README "Held-out test vs. full-dataset
metrics").

## 4. Leakage considerations (RQ1)

**Split methodology, verified by reading `backend/ml/train.py`:** a single
`train_test_split(X, y, test_size=0.2, random_state=42, stratify=y)` call — **random,
row-level, stratified by label**. Not temporal, not host-level, not file-level (there
is also only one capture file).

**What is and isn't measurable**, per `backend/evaluation/leakage_audit.py`:

| Check | Status | Result |
|---|---|---|
| Exact-duplicate rows (raw CSV, before cleaning) | MEASURED | 2,633 / 225,745 rows (1.1664%) |
| Exact duplicates surviving into train/test | MEASURED (structural) | Zero, by construction — `drop_duplicates()` runs before the split |
| Cross-label feature-vector collisions (post-cleaning) | MEASURED | 0 rows, 0 groups — no ambiguous-label rows found in this capture |
| Near-duplicate flows (standardized 1-NN distance, 2,000-row test sample) | MEASURED | median distance **0.0005**; **71.0%** of sampled test rows have a nearest training neighbor within 0.01 standardized Euclidean distance, **86.85%** within 0.1, **98.8%** within 1.0 |
| Rounding-based "family" grouping (3 significant figures) | MEASURED | 5.2348% of rows belong to a multi-row family |
| Temporal split | **NOT MEASURABLE** | No Timestamp column in the source CSV |
| Host-level split | **NOT MEASURABLE** | No Source/Destination IP column |
| File-level split | **NOT MEASURABLE** (moot) | Only one capture file exists |

**This is the single most important finding in this evaluation, stated with the
correct amount of caution below.** Exact-duplicate leakage is already prevented by
existing production code. The near-duplicate measurement shows the *vast majority* of
held-out test rows have an almost-identical (not identical) twin in the training set —
consistent with CICIDS2017's documented generation process (automated attack tooling
producing many highly similar flows) and with published critiques of this dataset
family (Engelen, Hammerschmidt & Verwer, *"Troubleshooting an Intrusion Detection
Dataset: the CICIDS2017 Case Study"*, 2021).

**What this evidence does and does not establish.** This measurement is **strong
evidence of substantial train/test similarity — a real near-duplicate structure in
this specific capture file that materially limits how much confidence the
near-ceiling accuracy can support as a generalization claim.** It is **not** a proof
that leakage caused the reported accuracy: no controlled experiment in this phase
directly isolates "near-duplicate structure" as a variable and measures accuracy with
it removed (the family-grouped split in §10/§16 is a step in that direction, but is
itself a weak, low-power control — see §10). The correct, fully-supported conclusion
is: *the near-duplicate structure is real, substantial, and undermines confidence in
treating the reported accuracy as evidence of learned generalization to genuinely
novel traffic* — not *the near-duplicate structure is proven to be the cause of the
reported accuracy*. See §5 for the follow-up experiment this motivates, and §13 for
how this shapes the internal-validity threat below.

## 5. Retrieval evaluation methodology (RQ2)

Phase 16's original set (3 hand-authored queries per category, ground truth = each
chunk's `threat_type` ingestion metadata) was audited and judged directionally sound
but statistically thin. Phase 17 expanded it to **5 queries per category (25 total)**,
each verified by re-reading the source `.txt` file it targets, paraphrasing a real
bullet point already present in that document (never inventing a topic the document
doesn't cover — see `retrieval_relevance.py`'s module docstring for the full
provenance note). Recall@k/Precision@k/HitRate@k/MRR@k are computed at k=3, 5, 10,
bypassing the production relevance threshold deliberately (measuring raw ranking
quality, not the accept/reject decision `retrieve_relevant()` makes separately).

This corpus has only 14 chunks across 5 categories — going meaningfully beyond 5
queries/category has diminishing value, since additional queries increasingly re-target
the same small chunk set rather than adding independent coverage. This is a real
ceiling of the current knowledge base, documented rather than worked around.

## 6. Hybrid retrieval evaluation methodology (RQ3)

Phase 16 already established, by reading `backend/intelligence/hybrid_retrieval.py`,
that hybrid retrieval in this architecture **augments** vector results with graph
evidence — it never re-ranks or filters them. Phase 17 kept that finding (re-verified,
`relevance_delta == 0.0` at every k on the expanded 25-query set) and added the
question the original result couldn't answer: **does the added graph evidence change
what the LLM actually writes**, even though it doesn't change retrieval ranking? See §7.

## 7. Graph contribution — downstream usefulness (RQ3, item 6)

`backend/evaluation/hybrid_downstream.py` builds two evidence contexts from the
IDENTICAL retrieved vector text — one with real graph evidence attached, one with
`graph_evidence=[]` — and calls the real `generate_analysis_fragment()` once against
each, for one query per category (5 cases, cost-bounded like `llm_evaluation.py`'s
`DEFAULT_CASES`).

| Metric | Result |
|---|---|
| Severity changed between conditions | 0.0% of cases |
| `attack_vectors` changed between conditions | 40.0% of cases |
| Indicators gained with graph evidence | 40.0% of cases |
| **Mitigations gained with graph evidence** | **40.0% of cases** |

Interpretation: severity judgment is stable regardless of graph evidence, but in 2 of
5 cases, removing graph evidence caused the LLM's own fallback fragment to produce
*fewer* mitigations than the graph-derived list would have — a genuine, measured
downstream contribution of the graph, separate from and not visible in the (correctly)
null retrieval-ranking result.

## 8. LLM evaluation methodology (RQ4)

Scoped to only the genuinely LLM-authored fields (`severity`, `summary`,
`attack_vectors`, the `insufficient_context` decision) — `threat`/`mitre_attack`/
`indicators`/`mitigations` are deterministically derived elsewhere in this
architecture (see README). Two tiers, kept explicitly separate:

- **Automated** (7 cases: 5 categories + 2 negative controls): `schema_valid_rate`
  1.0, on-topic correctness 1.0, off-topic correctness 1.0, non-empty
  `attack_vectors` rate 1.0, severity-present rate 1.0. All MEASURED.
- **Human rubric** (`severity_reasonableness`, `summary_grounding_quality`,
  `attack_vectors_relevance`, 0/1/2 scale): a ready-to-annotate CSV template is
  written to `evaluation/llm_rubric_template.csv` with real query/severity/summary/
  attack_vectors already populated. **Scores are IMPLEMENTED / NOT YET MEASURED** —
  this session did not fabricate scores by having an AI model annotate them, since
  that would collapse the automated/human distinction the task explicitly requires
  be preserved. A human annotator filling in that CSV is the only valid way to
  produce this number. Only one annotator is realistically available for a
  single-author thesis; **no inter-rater reliability statistic can be computed or
  claimed** unless a second independent annotator is recruited — documented here as
  an explicit limitation, not silently assumed away.

## 9. Grounding methodology and limitations (RQ4)

Two complementary, explicitly-labeled proxies — **neither is hallucination
detection, factuality detection, or truth verification**:

1. **Lexical-overlap proxy** (Phase 16, unchanged): a claim is "supported" if ≥40% of
   its significant words appear in the actual retrieved context text.
2. **Semantic proxy** (Phase 17, new): cosine similarity between a claim's sentence
   embedding and its best-matching context line, using the SAME
   `sentence-transformers/all-MiniLM-L6-v2` model already loaded for production RAG
   retrieval (`backend/rag/embeddings.py`) — **no new model downloaded, no cloud API
   called**, satisfying the task's explicit constraint.

Both scored **1.0** (5 cases, 8 total claims). Both remain proxies: the semantic
signal catches some paraphrases the lexical one misses (e.g. "steal login
credentials" vs. "harvest credentials"), but high cosine similarity means
*topically similar wording*, not *logically implied by the context* — a claim could
still be topically similar while asserting something the context never states. A
rigorous claim-level audit needs human annotation or a dedicated entailment/NLI
model; neither is implemented, and neither proxy is ever reported as "hallucination
rate" or "accuracy."

### Threshold selection audit — calibration leakage (Phase 17.1 self-review)

**The semantic threshold (cosine ≥ 0.5) is NOT independently validated, and this must
not be glossed over.** A subsequent audit of this session's own process found the
threshold was set by directly observing this proxy's real similarity score on one of
the exact five cases `run_grounding_evaluation()`'s default call later scores (the
phishing case, best-match similarity 0.7864) — the threshold was chosen *after seeing
results*, on the *same small evaluation set* it is later used to score, with no
independent held-out calibration set and no ground-truth labels (none exist for this
proxy to be tuned against). This is calibration leakage, structurally identical to
tuning a hyperparameter on the test set.

A sensitivity sweep was run to characterize how much this matters in practice:

| Threshold | supported_ratio_semantic (8 real claims) |
|---|---|
| 0.3 | 1.0 (8/8) |
| 0.4 | 1.0 (8/8) |
| 0.5 | 1.0 (8/8) |
| 0.6 | 1.0 (8/8) |
| 0.7 | 1.0 (8/8) |

The score is unchanged across the entire swept range for this specific sample —
most of the LLM's claims turned out to be near-verbatim copies of source bullet text
(cosine similarity exactly 1.0000), so this result happens not to be
threshold-sensitive here. A separate negative-control probe (4 deliberately unrelated
claims against the same phishing context) scored 0.24–0.38 — below every threshold
in 0.4–0.7, but **above** 0.3, meaning threshold=0.3 would have produced a false
positive on that probe while 0.4–0.7 would not have.

**Conclusion:** this sensitivity check shows the metric is not obviously degenerate
on the cases examined, but it does **not** retroactively validate 0.5 as a correct
threshold, and the calibration-leakage issue stands regardless of the outcome.
`mean_supported_ratio_semantic` should be read as **illustrative of this proxy's
behavior on this small, non-independently-calibrated case set** — not as a
scientifically validated grounding metric, and never as evidence about hallucination,
factuality, or truth.

## 10. Ablation methodology (RQ6)

Four conditions, each real production functions orchestrated (not modified), same
real DDoS rows and real query for every condition:

1. `ml_only` — classifier inference alone.
2. `ml_plus_vector` — classifier + vector-only retrieval (evidence coverage, no LLM).
3. `ml_plus_hybrid` — classifier + hybrid retrieval (evidence + graph coverage, no LLM).
4. `ml_plus_retrieval_plus_llm` — the full real pipeline.

An "LLM-only, retrieval-disabled" condition was deliberately **not** built: this
architecture's `analyze_query()` always resolves its primary threat from vector
retrieval, so there is no existing code path that runs the LLM with retrieval fully
disabled — building one purely for this experiment would be new production-adjacent
code, which the task instructions explicitly rule out.

## 11. Statistical methodology

- **ML accuracy** (n=44,617 held-out test samples): a **Wilson score interval** is
  reported — well-justified at this sample size, and preferred over the naive normal
  approximation because it stays within [0,1] even for a proportion this close to 1.
- **Retrieval Recall@5/Precision@5** (n=25 queries): a **bootstrap percentile
  interval** (2,000 resamples) is reported, explicitly flagged as descriptive rather
  than a precise population estimate below `MIN_N_FOR_INFERENCE` (30) —
  `backend/evaluation/statistics.py`.
- **No p-values or significance tests are computed anywhere in this phase.** Several
  natural-seeming comparisons (vector-only vs. hybrid) share the exact same underlying
  ranked list rather than being independent samples, so a significance test would be
  statistically meaningless there; elsewhere, sample sizes (5–25 cases for LLM/
  grounding/ablation experiments) don't justify one. Per experiment where this
  applies: *"Descriptive evaluation only; sample size/design does not justify
  significance testing."*

## 12. Reproducibility

Every report includes an `environment` block: OS/release, Python version, `ollama
--version` CLI output, model name, a SHA-256-truncated hostname (never raw), and the
random seed — imported directly from `backend/ml/config.RANDOM_STATE`, never
duplicated. Run with:

```bash
uv run python -m backend.evaluation --full --output evaluation/latest.json
```

Machine-readable output: `evaluation/latest.json`. Human-readable tables, generated
FROM that JSON (never hand-typed): `evaluation/thesis_tables.md`, regeneratable
standalone via `uv run python -m backend.evaluation.thesis_tables`.

## 13. Threats to validity

- **Internal validity (the dataset itself):** the near-duplicate finding in §4 —
  substantial train/test similarity, not proven causation — means the ~99.99%
  accuracy figure should not be read as strong evidence of learned generalization to
  genuinely novel traffic. No controlled experiment in this phase isolates
  near-duplicate structure as a variable and re-measures accuracy with it removed, so
  this thesis does not claim to have proven leakage caused the reported score — only
  that a real, substantial near-duplicate structure exists in this specific capture
  (consistent with this dataset family's documented properties in the literature) and
  materially weakens confidence in the generalization claim.
- **Construct validity (retrieval ground truth):** relevance judgments come from
  ingestion-time chunk metadata (a real, verifiable property of the knowledge base),
  not an independently-curated external relevance judgment set.
- **Construct validity (grounding proxies):** neither lexical nor semantic grounding
  proxy performs true fact verification; both can be fooled by superficial word/topic
  overlap without genuine logical support.
- **External validity (LLM evaluation):** 7 automated cases and 5 grounding/
  downstream cases are a small, hand-authored set reflecting this project's 5 known
  threat categories — not a general claim about LLM-based threat analysis quality
  beyond this specific knowledge base.
- **Statistical power:** most Phase 17 experiments beyond ML classification operate
  on samples of 5–25 — genuine, real measurements, but not powered for strong
  population-level claims; every report/table says so explicitly rather than
  implying otherwise.
- **No second annotator:** the human LLM-quality rubric, if and when filled in, will
  reflect a single annotator's judgment with no inter-rater reliability check.

## 14. Results

See `evaluation/thesis_tables.md` (regenerate via the command in §12) for the full,
current machine-generated Tables 1–7. Summary of what changed vs. Phase 16 and what's
new in Phase 17:

- **Table 1 (ML performance):** unchanged from Phase 16, now with a Wilson 95% CI on
  held-out accuracy: **[0.999769, 0.999965]**.
- **Table 2 (leakage/generalization) — new:** the leakage audit (§4) plus a
  research-only family-grouped-split retrain: accuracy **0.999888** vs. baseline
  **0.999910** — nearly identical, but this comparison has limited power since only
  ~5.2% of rows fall into a multi-row family at the grouping precision used (see §16
  for why this doesn't contradict §4's stronger finding). 5-seed repeated-random-split
  variance: mean 0.999910, stddev 0.000045 — confirms the reported number isn't a
  lucky single seed.
- **Table 3 (retrieval) — expanded:** 25 queries now (was 15); Recall@5 = 0.9467,
  Precision@5 = 0.528, with a bootstrap 95% CI of [0.88, 1.00].
- **Table 4 (hybrid) — extended:** relevance_delta confirmed exactly 0.0 at every k
  on the larger query set; new downstream-usefulness result (§7): mitigations gained
  in 40% of cases when graph evidence was present.
- **Table 5 (LLM) — extended:** automated metrics unchanged (all 1.0); grounding now
  reports both lexical (1.0) and semantic (1.0) proxies.
- **Table 6 (latency) — new reliability data:** 20/20 repeated end-to-end runs
  succeeded (success rate 1.0); total latency mean 5632ms, stddev 216ms, p95 6039ms.
  Per-stage `stddev_ms` now reported alongside mean/p50/p95/min/max.
- **Table 7 (ablation) — new:** progressive latency/evidence cost across the four
  conditions, confirming the LLM stage dominates end-to-end cost by roughly two
  orders of magnitude, consistent with Phase 16's finding.

## 15–20. Additional context

See the Phase 17 turn's final chat report (and its git-diff-verified file list) for:
which specific experiments are MEASURED vs. IMPLEMENTED/NOT YET MEASURED vs. NOT
MEASURABLE, new/modified files, exact test counts, and the complete limitations list —
kept in the conversation record rather than duplicated here to avoid two copies
drifting apart. This document is the durable, versioned methodology reference; the
chat report is the point-in-time delivery summary.
