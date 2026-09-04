# LLM Rubric Annotation Guide (Phase 18, P0.2)

## Purpose

`backend/evaluation/llm_evaluation.py` measures the LLM analysis pipeline's
**automated, structural** correctness (does it produce schema-valid output, does it
correctly recognize an on-topic vs. off-topic query). It cannot measure whether the
LLM's actual *content* — the severity judgment, the summary, the attack vectors — is
genuinely **good**. That requires human judgment, which this guide is for.

This rubric measures **evidence-supported output quality**: does the LLM's generated
analysis reflect and stay consistent with the retrieved threat-intelligence text it
was actually given? It is **not** hallucination detection, factuality detection, or
truth verification — it is a human rubric assessment of generated analysis quality
relative to the supplied evidence, nothing more. Judge every case against the
`retrieved_context_excerpt` column in front of you, never against your own outside
knowledge of phishing, ransomware, DDoS, SQL injection, or botnets — a
technically-accurate-in-general statement that the retrieved excerpt does not
actually support should score low, and a statement the excerpt does support should
score well even if you personally know a more complete or nuanced version.

## What you are annotating

`evaluation/llm_rubric_template.csv` (regenerate with `uv run python -m
backend.evaluation --llm` if you need a fresh copy) has one row per evaluated case,
including the LLM's real generated `severity`/`summary`/`attack_vectors` and the
`retrieved_context_excerpt` — the actual retrieved threat-intelligence text those
fields were supposed to be grounded in.

**Copy the template to your own file before scoring** — never edit
`llm_rubric_template.csv` in place. Name your copy
`evaluation/llm_rubric_annotations_<your_id>.csv` (e.g.
`evaluation/llm_rubric_annotations_alex.csv`). This keeps the original template
(and any other annotator's file) untouched, and lets
`backend/evaluation/llm_rubric_scoring.py` score multiple annotators' files
independently and compare them.

## Case selection: which rows do you score?

The template has **7 cases**. **5 are on-topic** (case_ids 0–4 in the default set:
phishing, ransomware, DDoS, SQL injection, botnet) — score these on all three
dimensions. **2 are negative controls** (case_ids 5–6: an off-topic query like "What
is the capital of France?"), marked `is_negative_control=True`. **Leave every score
column blank for negative-control rows.** There is no generated analysis content to
judge quality of — the correct system behavior for these is to produce no analysis
at all, and that structural behavior is already checked automatically (you don't need
to verify it). If you accidentally put a score in a negative-control row, the
scoring script will detect it, exclude it, and log it — it will never silently count
toward any mean — but please leave these blank regardless.

## The three rubric dimensions

Score each on-topic case on all three, using the same 0/1/2 scale:

```
0 = incorrect
1 = partially correct
2 = correct
```

### 1. `severity_reasonableness`

*Is the assigned severity (Low/Medium/High/Critical) a reasonable judgment given the
retrieved evidence?*

- **2 (correct):** The severity is a defensible reading of the retrieved evidence —
  e.g. the excerpt describes credential theft or data encryption and the analysis
  says "High."
- **1 (partially correct):** The severity isn't unreasonable, but the excerpt doesn't
  clearly support that exact level (e.g. the excerpt is fairly generic and "Medium"
  would have been just as defensible as "High").
- **0 (incorrect):** The severity contradicts or is unsupported by the excerpt (e.g.
  "Low" for a ransomware case whose excerpt describes file encryption and ransom
  demands).

### 2. `summary_grounding_quality`

*Does the summary genuinely reflect the retrieved threat-intelligence content, rather
than generic or invented claims?*

- **2 (correct):** Every substantive claim in the summary traces back to something in
  `retrieved_context_excerpt`.
- **1 (partially correct):** The summary is broadly on-topic and not wrong, but is
  generic/vague enough that it could have been written without reading the excerpt
  at all (e.g. "Phishing attacks impersonate trusted entities to steal sensitive
  information" when the excerpt actually lists specific techniques like fake login
  pages and business email compromise that the summary never mentions).
- **0 (incorrect):** The summary states something the excerpt does not support, or
  contradicts it.

### 3. `attack_vectors_relevance`

*Are the listed attack vectors genuinely relevant to and supported by this specific
threat's evidence?*

- **2 (correct):** Every listed vector appears in, or is a clear restatement of,
  something in the excerpt.
- **1 (partially correct):** Some vectors are supported, others are generic filler
  or only loosely related.
- **0 (incorrect):** The vectors are unsupported by the excerpt, or belong to a
  different threat category entirely.

## Worked example (real case from this project)

**Case:** `query="Explain phishing attacks and how they steal credentials"`,
`attack_vectors="Credential harvesting through fake login pages or malicious links"`.

If `retrieved_context_excerpt` contains the line `"- fake login pages"` and
`"- credential harvesting"` (it does, in this project's real `phishing.txt`), this
attack-vector claim is **directly supported** → score **2**.

If instead the generated attack vector had been `"Zero-day exploitation of browser
memory corruption"` — technically a real category of attack in general, but **not
present anywhere in the excerpt** — that would score **0**, regardless of whether you
personally know that's a real attack technique. You are scoring *supported-by-this-
evidence*, not *true in general*.

## Missing / invalid scores

- **Leave a cell blank** if you're unsure or haven't gotten to it yet — a blank cell
  is recorded as `"unscored"` and excluded from the mean. It is never silently
  treated as a 0.
- **Only write exactly `0`, `1`, or `2`** in a score cell. Anything else (a word, a
  decimal, a score outside 0–2) is recorded as `"invalid"`, excluded from the mean,
  and logged with the original text so it can be reviewed — it will never crash the
  scoring script and never be silently coerced into a number.

## Second-annotator instructions

If a second person also annotates the same cases:

1. They should copy the **original, unmodified** `llm_rubric_template.csv` (not your
   filled-in copy) into their own `evaluation/llm_rubric_annotations_<their_id>.csv`,
   so neither annotator sees the other's scores while annotating.
2. Run:
   ```bash
   uv run python -m backend.evaluation.llm_rubric_scoring \
       evaluation/llm_rubric_annotations_<id1>.csv \
       evaluation/llm_rubric_annotations_<id2>.csv
   ```
   This computes percent exact agreement and Cohen's weighted kappa (linear weights,
   appropriate for this ordinal 0/1/2 scale) per dimension, over the on-topic cases
   both annotators actually scored. No significance test is computed on kappa
   itself, or anywhere in this workflow — 5 on-topic cases does not justify one.
3. With only one annotator, no inter-rater statistic is computed or claimed at all —
   this is the correct, honest result of having one annotator, not a gap to work
   around.

## A critical, unavoidable limitation

**If you are the thesis author, your own annotation is not an independent quality
judgment.** State this explicitly wherever these scores are reported — do not let it
be implied away by presenting a mean score without this caveat attached. A second,
genuinely independent annotator (see above) is the only way to address this; absent
one, report the single-annotator scores as exactly what they are: one person's
(the system's own author's) judgment, descriptive only, not a validated or
independently-corroborated quality measurement.
