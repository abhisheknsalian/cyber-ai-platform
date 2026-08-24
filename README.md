# Cyber AI Platform

A local, retrieval-augmented cybersecurity threat-intelligence analysis platform: a React
dashboard backed by a FastAPI service. The backend embeds a small knowledge base of threat
write-ups (`data/threat_intel/*.txt`) into a Chroma vector store and uses a locally-running
Llama 3.2 model (via [Ollama](https://ollama.com)) to turn a natural-language question into a
**validated, structured JSON threat analysis** with source attribution. A separate Random
Forest classifier (trained offline on CICIDS2017-style network flow data) can also score a
traffic sample as BENIGN/DDoS and feed that prediction into the same RAG pipeline. See
**ML Detection Pipeline** below.

## Architecture

```text
React dashboard (Vite + TypeScript + Tailwind)
   → FastAPI (POST /analyze, GET /health, GET /threats, POST /classify, POST /analyze/classification)
   → relevance-filtered retrieval (ChromaDB + HuggingFace embeddings)
   → deterministic threat-type identification + MITRE ATT&CK extraction (from source docs)
   → structured LLM generation (Ollama / Llama 3.2, JSON-schema constrained)
   → validated Pydantic response with source attribution
   → React

Network Traffic Features (CICFlowMeter-style)
   → Random Forest (backend/ml/) → BENIGN / DDoS prediction
   → same threat-identification + RAG + LLM pipeline above → structured threat report
```

Out-of-domain or unsupported queries never reach the LLM at all: if nothing in the knowledge
base is actually relevant, the API returns a `no_relevant_intelligence` result directly from the
retrieval layer. See **Relevance Filtering** below.

## Requirements

- Python 3.12+
- [uv](https://docs.astral.sh/uv/)
- Node.js 20+ and npm (for the frontend)
- [Ollama](https://ollama.com), installed and running locally

## Running the Project

### Backend

```bash
uv sync
uv run python -m backend.rag.ingestion   # build the vector store (see below)
uv run python -m backend.ml.train         # optional: train the DDoS classifier (see below)
uv run uvicorn backend.main:app --reload
```

`uv sync` installs FastAPI, LangChain, ChromaDB, sentence-transformers, the Ollama client,
scikit-learn, joblib, pytest, and the existing notebook/ML dependencies into a local `.venv`.
The classifier training step is optional -- `/analyze`, `/health`, and `/threats` all work
without it; only `/classify` and `/analyze/classification` need a trained model.

### Frontend

```bash
cd frontend
npm install
cp .env.example .env   # only needed if the backend isn't on the default http://localhost:8000
npm run dev
```

Opens at `http://localhost:5173`. It talks to the backend at the URL in `VITE_API_URL` (see
**Frontend** below).

## Ollama

Ollama must be installed and running separately — it is not managed by this project.

```bash
# start the Ollama daemon (if not already running)
ollama serve

# pull the model used by the backend (only needs to be done once)
ollama pull llama3.2:3b
```

The model name defaults to `llama3.2:3b` and can be overridden with the `OLLAMA_MODEL`
environment variable.

## Build the Vector Database

The Chroma vector store is not committed to git — it must be built locally from the tracked
threat-intelligence documents in `data/threat_intel/`:

```bash
uv run python -m backend.rag.ingestion
```

This discovers every `.txt` file in `data/threat_intel/`, chunks it, embeds it, and writes a
fresh Chroma collection to `rag/chroma_db/` (also gitignored). Each run wipes and rebuilds the
collection from scratch, so it's safe to re-run any time the source documents change — it never
accumulates stale or duplicate chunks.

## Backend Endpoints

- `GET /` — basic liveness message
- `GET /health` — API/vector-store/LLM status (does not run LLM inference — see below)
- `GET /threats` — threat categories discovered from `data/threat_intel/*.txt`, for the frontend
- `POST /analyze` — structured, retrieval-grounded threat analysis
- `POST /classify` — DDoS/BENIGN network-traffic classification (Random Forest); see **ML Detection Pipeline**
- `GET /ml/feature-importance` — the trained model's own `feature_importances_`, ranked
- `POST /analyze/classification` — takes an already-computed classifier prediction and runs it through the same RAG pipeline as `/analyze`
- `GET /docs` — interactive Swagger UI

`GET /health` response:

```json
{
  "status": "ok",
  "vector_store": { "available": true, "chunk_count": 14, "collection": "threat_intel" },
  "llm": { "model": "llama3.2:3b", "reachable": true, "model_pulled": true }
}
```

`llm.reachable`/`model_pulled` come from listing installed Ollama models (`ollama.list()`) — this
is a status check, not a generation call, so `/health` still never invokes the LLM.

## API Contract

**This is a breaking change from the earlier query-parameter version** — `/analyze` now takes a
JSON body and returns a structured, validated response instead of free-form text.

### Request

```http
POST /analyze
Content-Type: application/json

{
  "query": "Explain phishing attacks and mitigation"
}
```

`query` must be 1–2000 characters after trimming whitespace; a blank or whitespace-only query is
rejected with `422`.

### Response

```json
{
  "query": "Explain phishing attacks and mitigation",
  "status": "analyzed",
  "threat": "phishing",
  "severity": "High",
  "summary": "Phishing is a cyberattack technique where attackers impersonate trusted entities to steal sensitive information.",
  "attack_vectors": ["suspicious URLs", "urgent language", "fake domains", "spelling mistakes", "unexpected attachments"],
  "mitre_attack": [
    { "id": "T1566", "name": "Phishing" },
    { "id": "T1598", "name": "Phishing for Information" }
  ],
  "indicators": ["email spoofing", "fake login pages", "credential harvesting", "malicious links"],
  "mitigations": ["employee awareness training", "email filtering", "multi-factor authentication"],
  "sources": [
    { "source": "phishing.txt", "threat_type": "phishing", "chunk_index": 6, "score": 0.6737 }
  ]
}
```

| Field | Meaning |
|---|---|
| `status` | `"analyzed"` or `"no_relevant_intelligence"` — always check this first |
| `threat` | The identified threat type, derived from the top-matching document's metadata (not LLM-generated) |
| `severity` | An LLM-generated qualitative judgment (`Low`/`Medium`/`High`/`Critical`) — **not** sourced from the knowledge base, which contains no severity ratings |
| `summary`, `attack_vectors`, `indicators`, `mitigations` | Generated by the LLM, constrained to only use the retrieved context |
| `mitre_attack` | Parsed directly out of the matched source `.txt` file(s) via regex — the LLM never generates this field, so a technique can only appear if it's genuinely present in the knowledge base |
| `sources` | Every retrieved chunk that supported the answer, with its filename, threat type, chunk index, and relevance score |

For an out-of-domain query (e.g. "What is the capital of France?"), the LLM is never called:

```json
{
  "query": "What is the capital of France?",
  "status": "no_relevant_intelligence",
  "threat": null,
  "severity": null,
  "summary": "No relevant threat intelligence was found in the knowledge base for this query. This system only answers questions covered by its threat-intelligence documents (botnets, DDoS, phishing, ransomware, SQL injection).",
  "attack_vectors": [], "mitre_attack": [], "indicators": [], "mitigations": [], "sources": []
}
```

### Error Responses

| Status | Cause |
|---|---|
| `422` | Empty/blank query, or query over 2000 characters (Pydantic validation) |
| `503` | Vector store hasn't been built yet, or Ollama is unreachable |
| `502` | Ollama returned a response that didn't match the required JSON schema |
| `500` | Any other unexpected error (logged server-side; no stack trace is returned to the client) |

### Example curl calls

```bash
# A supported threat type
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"query": "How can DDoS attacks be mitigated?"}'

# Out-of-domain — returns status: "no_relevant_intelligence", not a fabricated report
curl -X POST http://127.0.0.1:8000/analyze \
  -H "Content-Type: application/json" \
  -d '{"query": "What is the capital of France?"}'
```

## Relevance Filtering

Chroma's default collection distance is squared-L2, so **lower scores mean more similar**. The
retrieval layer (`backend/rag/retrieval.py`) fetches the top `RAG_TOP_K` candidates and keeps
only those with `score <= RAG_SCORE_THRESHOLD`; if nothing survives, the query is treated as
`no_relevant_intelligence` before the LLM is ever called.

The default threshold (`1.5`) was chosen empirically, by running `similarity_search_with_score`
for on-topic and off-topic queries against the real knowledge base:

| Query type | Example | Best-match score |
|---|---|---|
| On-topic | "Explain phishing attacks and mitigation" | 0.67 |
| On-topic | "Explain ransomware attacks" | 0.36 |
| On-topic | "How can DDoS attacks be mitigated?" | 0.54 |
| Off-topic | "What is the capital of France?" | 1.77 |
| Off-topic | "How do I bake a chocolate cake?" | 1.77 |

On-topic chunks scored 0.36–1.33 across all five threat types (including secondary matches);
off-topic queries never scored below 1.77. `1.5` sits in that gap with margin on both sides.

This is a small (14-chunk) knowledge base, so this threshold is a reasonable starting point, not
a rigorously tuned production value — re-run the same empirical check if the knowledge base grows
significantly.

## Threat Identification & MITRE ATT&CK Handling

- **Threat type** is the `threat_type` metadata of the single best-scoring retrieved chunk — not
  something the LLM infers. If a query's top match is ambiguous between two threats, only the
  single best match is reported; there is no multi-threat response yet.
- **MITRE ATT&CK techniques** are extracted with a regex (`T\d{4}: <name>`) directly from the
  source `.txt` file(s) matching the identified threat — never generated by the LLM. The five
  current documents only contain one or two techniques each; **this is not a MITRE ATT&CK
  database** — techniques not present in these five files (including sub-techniques, tactics, or
  related groups/software) simply won't appear, no matter what's asked.

## ML Detection Pipeline

**The classifier is trained on CICIDS2017-style network traffic and currently detects DDoS vs
BENIGN traffic. It is not a general-purpose malware detector or a real-time network monitoring
system.** `POST /classify` scores one already-extracted CICFlowMeter feature vector offline —
there is no packet capture, no live traffic ingestion, and no fabricated "live" dashboard.

```text
CICIDS2017 CSV (Friday-Afternoon-DDoS capture)
   → preprocessing (backend/ml/preprocessing.py): strip columns, drop inf/NaN, drop duplicates
   → train/test split (stratified, random_state=42)
   → RandomForestClassifier(n_estimators=100, random_state=42)
   → saved to models/ddos_random_forest.joblib (gitignored)

At inference:
NetworkTrafficFeatures (validated Pydantic request)
   → backend/ml/predictor.py: load saved model, predict + predict_proba
   → ClassificationResult (prediction, probability, model)
   → optionally: backend/services/classification.py maps DDoS → the same RAG query used by
     the Threat Analysis page → ThreatAnalysis (identical shape to /analyze's response)
```

### Getting the dataset

The CICIDS2017 "Friday-Afternoon-DDoS" CSV (~225k rows, 79 columns) is **not committed to this
repo** and is not downloadable via a plain public URL — CIC now gates it behind a registration
form at cicresearch.ca (name/email/organization). Register there yourself, download
`Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv`, and place it at:

```text
data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv
```

(or point `DDOS_DATASET_PATH` at wherever you saved it).

### Training

```bash
uv run python -m backend.ml.train
```

Prints class distribution, a full classification report (including DDoS-specific
precision/recall/F1), and the confusion matrix, then saves the model to
`models/ddos_random_forest.joblib` and a metrics/metadata JSON alongside it. `models/` is
gitignored — the artifact is never committed. Training and inference are fully separate: the
API only ever loads the saved `.joblib` file (`backend/ml/predictor.py`); it never fits a model.

### Data leakage audit and fix

The original notebook (`notebooks/01_data_exploration.ipynb`) reported 99.99% accuracy / 1.00
precision-recall-F1 across the board. That result should not be trusted at face value. Auditing
the notebook's code found:

- No leakage from preprocessing-before-split in the classic sense (no scaler or encoder was fit
  on the full dataset before splitting).
- **No `drop_duplicates()` call anywhere before `train_test_split`.** CICIDS2017 -- and this
  specific Friday-Afternoon-DDoS capture -- is documented in ML-security literature (e.g.
  Engelen, Rimmer & Joosen, *"Troubleshooting an IDS Dataset: the CICIDS2017 Case Study"*, 2021)
  to contain large numbers of duplicate/near-duplicate flow records. Combined with a plain random
  80/20 split, duplicate rows can land in both train and test, letting the model "recognize" a
  test row it already memorized during training -- the textbook explanation for suspiciously
  perfect metrics on this exact dataset.
- `train_test_split` also didn't use `stratify=y` (minor; classes were already fairly balanced).

**Fix applied** in `backend/ml/preprocessing.py::load_and_clean_dataset`: deduplicate the full
cleaned dataset before the split (and log how many rows were removed), and stratify the split.
The model architecture and hyperparameters are unchanged (`RandomForestClassifier(n_estimators=100,
random_state=42)`), per Phase 4 scope -- only the leakage is fixed, not the model.

**Honest metrics from this fix have not been produced yet.** The real 225k-row dataset was not
available in this environment (see below), so real retraining hasn't run. Do not treat any
number printed by a training run against a placeholder/synthetic dataset as a real evaluation
result -- see **Known Limitations**.

### Feature schema and validation

`backend/ml/config.py::FEATURE_COLUMNS` is the single source of truth for the 78 trained feature
names (in training order) -- both `backend/ml/schemas.py`'s Pydantic request model and
`frontend/src/types/ml.ts` are generated from (or kept in lockstep with) this same list, so the
request schema can never silently drift from what the model was actually trained on. Every field
is required, extra fields are rejected (`extra="forbid"`), and NaN/Infinity/non-numeric values
are rejected with a validation error -- untrusted traffic input is never passed straight to the
model.

### Explainability

`GET /ml/feature-importance` returns the trained model's own `feature_importances_`, ranked --
nothing is invented or hand-labeled.

### Classifier + RAG integration

`POST /analyze/classification` takes an already-computed prediction (e.g. from `/classify`), not
raw features:

```json
// request
{ "prediction": "DDoS", "probability": 0.98 }
```

```json
// response
{
  "classification": { "prediction": "DDoS", "probability": 0.98, "model": "random_forest", "classification": "malicious" },
  "analysis": {
    "threat": "ddos_attack", "severity": "High", "mitre_attack": [{ "id": "T1498", "name": "Network Denial of Service" }],
    "indicators": [...], "mitigations": [...], "sources": [...]
  }
}
```

`BENIGN` is a valid, expected prediction -- it returns `"analysis": null` rather than fabricating
a threat report for non-malicious traffic; the LLM is never called in that case.

## Frontend

`frontend/` is a React + TypeScript dashboard built with Vite and styled with Tailwind CSS —
a dark, SOC-style interface for the API above. No other UI framework is used; components are
hand-built with Tailwind.

- **Dashboard** (`/`) — live `GET /health` + `GET /threats` data: knowledge-base size, supported
  threat types, RAG status (vector store available + chunk count), LLM status (model reachable /
  pulled). No fabricated metrics — anything not knowable from the API is shown as unavailable.
- **Threat Analysis** (`/analyze`) — the query form, sample-query chips, loading state, and the
  full structured result: threat/severity, attack vectors, indicators, MITRE ATT&CK (each
  technique links to its real `attack.mitre.org` page), mitigations, and sources with relevance
  scores. A `no_relevant_intelligence` response renders as a distinct empty state, never a
  fabricated report.
- **Network Detection** (`/detection`) — paste a CICFlowMeter-style JSON feature vector (or use
  "Fill example shape" for an all-zero shape reference, not real traffic), classify it, then
  optionally "Analyze Threat" to run the resulting prediction through the same RAG pipeline and
  render it with the same `AnalysisResult` component as the Threat Analysis page. A `BENIGN`
  result renders a distinct "no threat detected" state instead of a fabricated report.
- **Threat Intelligence** (`/intelligence`) — the threat categories from `GET /threats`, i.e.
  exactly what's in `data/threat_intel/`.
- **About** (`/about`) — architecture explanation; states plainly what is and isn't implemented.
- **Login** — shown instead of the app for an unauthenticated session (see **Authentication**).
  `AuthProvider`/`useAuth` (`frontend/src/context/AuthContext.tsx`) call `GET /auth/me` on startup,
  gate all five pages above behind `authenticated`, and drop back to the login page automatically
  if any request ever comes back `401`. The sidebar's "Log out" button calls `POST /auth/logout`.

**API integration**: `frontend/src/services/api.ts` is the only place that calls `fetch`;
`analyzeThreat`/`getHealth`/`getThreats`/`classifyTraffic`/`getFeatureImportance`/`analyzeClassification`
are typed against `frontend/src/types/api.ts` and `frontend/src/types/ml.ts`, which mirror the
backend Pydantic models field-for-field. Requests time out after 60s. Every failure mode (backend
unreachable, timeout, non-2xx, malformed JSON, structured validation errors) is normalized into a
single `ApiError` with a user-facing message — no raw errors or stack traces reach the UI.

**Configuration**: the backend URL is read from `VITE_API_URL` (see `frontend/.env.example`),
defaulting to `http://localhost:8000` if unset. Never commit `frontend/.env`.

**CORS**: the backend explicitly allows only `http://localhost:5173` (the Vite dev server), with
`allow_credentials=True` so the session/CSRF cookies can be sent — never a wildcard origin, which
is a hard requirement for combining CORS with credentials in the first place.

## Configuration

All settings have sane local defaults and can be overridden with environment variables:

| Variable | Default | Purpose |
|---|---|---|
| `OLLAMA_MODEL` | `llama3.2:3b` | LLM used for structured generation |
| `EMBEDDING_MODEL` | `sentence-transformers/all-MiniLM-L6-v2` | Embedding model for both ingestion and retrieval |
| `THREAT_INTEL_DIR` | `data/threat_intel` | Source documents for ingestion |
| `CHROMA_PERSIST_DIR` | `rag/chroma_db` | Where the vector store is persisted |
| `CHROMA_COLLECTION` | `threat_intel` | Chroma collection name |
| `CHUNK_SIZE` | `300` | Chunk size (characters) used during ingestion |
| `CHUNK_OVERLAP` | `50` | Chunk overlap (characters) used during ingestion |
| `RAG_TOP_K` | `5` | Candidate chunks retrieved before relevance filtering |
| `RAG_SCORE_THRESHOLD` | `1.5` | Max distance score to be considered relevant (lower = more similar) |
| `DDOS_DATASET_PATH` | `data/raw/Friday-WorkingHours-Afternoon-DDos.pcap_ISCX.csv` | CICIDS2017 CSV used by `backend.ml.train` |
| `ML_MODEL_DIR` | `models` | Where the trained classifier artifact + metadata are saved/loaded |
| `CYBER_AI_API_KEY` | *(unset)* | API key for direct API clients — see **Authentication** below. No default |
| `CYBER_AI_USERNAME` | *(unset)* | Browser login username — see **Authentication** below. No default |
| `CYBER_AI_PASSWORD` | *(unset)* | Browser login password — see **Authentication** below. No default |

## Authentication

`POST /analyze`, `POST /classify`, `GET /ml/feature-importance`, and `POST /analyze/classification`
require authentication. `GET /`, `GET /health`, `GET /threats`, and `GET/POST /auth/*` stay public.
There are two independent credential paths, either of which satisfies a protected request:

```text
Direct API client:  Authorization: Bearer <CYBER_AI_API_KEY>  ─┐
                                                                 ├─→ protected endpoint
Browser:             HttpOnly session cookie (+ CSRF header)  ─┘
```

### Direct API clients

```bash
export CYBER_AI_API_KEY="choose-your-own-local-value"   # never commit this
uv run uvicorn backend.main:app --reload
```

```bash
curl -H "Authorization: Bearer $CYBER_AI_API_KEY" http://127.0.0.1:8000/classify -d '...'
```

If `CYBER_AI_API_KEY` isn't set, the API still starts (public endpoints keep working) but this
path is always rejected with `401` — there is no default key. The key is compared with a
constant-time comparison (`hmac.compare_digest`) and is never logged, echoed in a response, or
included in the OpenAPI schema.

### Browser (the React frontend)

**The frontend never receives or sends `CYBER_AI_API_KEY`.** It's a static, client-side-only SPA
with no backend-for-frontend proxy, so there is nowhere to hold that secret a browser couldn't
also read out of the shipped JS bundle. Instead, the frontend uses a server-side session:

```text
POST /auth/login {username, password}
   → backend/services/auth.py validates against CYBER_AI_USERNAME / CYBER_AI_PASSWORD
     (hmac.compare_digest, both fields always compared so timing can't reveal which was wrong)
   → backend/sessions.py creates an in-memory session: a cryptographically random
     token (secrets.token_urlsafe(32)), no user data or secrets encoded in it
   → two cookies are set:
       cyber_ai_session  -- HttpOnly, Secure, SameSite=None -- the actual credential,
                             unreadable by JS
       cyber_ai_csrf     -- NOT HttpOnly, Secure, SameSite=None -- a paired token the
                             frontend reads and echoes back as X-CSRF-Token on every
                             state-changing (non-GET) request ("double-submit" CSRF
                             defense; see backend/sessions.py)
```

```bash
export CYBER_AI_USERNAME="choose-your-own-local-username"
export CYBER_AI_PASSWORD="choose-your-own-local-password"
```

`SameSite=None` is required (not a weaker choice) because the frontend (`:5173`) and backend
(`:8000`) are different origins — a stricter SameSite cookie is simply never sent on that
cross-origin `fetch`. That in turn removes the browser's own CSRF mitigation, which is why the
double-submit CSRF header exists on top of it. CORS is locked to the exact frontend origin with
`allow_credentials=True` (never a wildcard) as the other half of that defense.

Sessions are stored in-process (`backend/sessions.py`) and are lost on restart — appropriate for
this single-process local application; there is no database or Redis dependency for it.

`GET /auth/me` (public, always `200`) is how the frontend asks "am I logged in?" on startup.
`POST /auth/logout` destroys the session server-side and clears both cookies. Neither endpoint,
nor `/auth/login`, ever returns the session token, CSRF token, password, or API key in a response
body — only the two cookies carry them, and the CSRF cookie carries a value that's useless without
the paired HttpOnly session cookie a script can't read.

**Known limitation:** if a protected request ever returns `401` (e.g. session expired), the
frontend drops back to the login page (see `AuthContext`) — but there's no automatic retry of the
in-flight request after re-login; the user re-submits it.

## Docker Backend

A production-style container for the **FastAPI backend only** (Phase 6.1). The frontend, Ollama,
the trained Random Forest model, the CICIDS2017 dataset, and the Chroma vector store are all
intentionally **not** part of this image:

- **The CICIDS2017 dataset is not included in the image.** It's gitignored and was never part of
  the build context beyond `.dockerignore` explicitly excluding it a second time.
- **The trained classifier is not included in the image.** `models/` is empty in the built image
  (just an owned, writable mount point) — the real `.joblib` + metadata are supplied at runtime.
- **No secrets are included in the image.** `CYBER_AI_API_KEY`, `CYBER_AI_USERNAME`,
  `CYBER_AI_PASSWORD`, and `OLLAMA_*` are all read from the container's environment at runtime,
  never baked in.
- **Ollama is external to this container.** It is not installed inside the image; the backend
  reaches it over the network via `OLLAMA_HOST`.

### Prerequisites

- Docker
- A trained model at `models/ddos_random_forest.joblib` (+ its metadata JSON) — see **ML Detection
  Pipeline** above for how to produce it; it is not built inside the container in this phase.
- A built Chroma vector store at `rag/chroma_db/` — see **Build the Vector Database** above.
- Ollama running and reachable from the container (see below).

### Build

```bash
docker build -t cyber-ai-backend .
```

Two stages: the first resolves the existing `pyproject.toml`/`uv.lock` dependency set with `uv
sync --frozen --no-dev --no-install-project` (reproducible install, no second dependency list, no
dev/test tooling); the second is a fresh `python:3.12-slim` image containing only that installed
virtualenv plus `backend/` and `data/threat_intel/` — never `COPY . .`. `data/threat_intel/*.txt`
is a genuine runtime dependency, not just an ingestion-time one: `backend/services/
knowledge_base.py` (`GET /threats`) and `backend/services/threat_analysis.py`'s MITRE extraction
both read those files directly on every request, so they're copied into the image (they're
tracked in git and contain nothing sensitive).

### Required environment variables

| Variable | Required | Purpose |
|---|---|---|
| `CYBER_AI_API_KEY` | Yes, for direct API clients | See **Authentication** |
| `CYBER_AI_USERNAME` / `CYBER_AI_PASSWORD` | Yes, for browser/session auth | See **Authentication** |
| `OLLAMA_HOST` | Yes | Where Ollama is reachable from inside the container — see below |
| `OLLAMA_MODEL` | No (defaults to `llama3.2:3b`) | Passed through unchanged |
| `CORS_ORIGINS` | No (defaults to `http://localhost:5173`) | Comma-separated list of allowed browser origins — see **Docker Compose** below for why the Dockerized frontend needs this changed |
| Everything in **Configuration** above | No | Same env vars, same defaults, work identically in the container |

### Required volume mounts

| Container path | Contents | Mode |
|---|---|---|
| `/app/models` | `ddos_random_forest.joblib` + `.metadata.json` | Read-only is fine — `joblib.load()` only reads |
| `/app/rag/chroma_db` | The built Chroma collection | **Must be read-write**, not read-only — Chroma opens the SQLite file in a mode that needs to write WAL/journal files even for pure reads. A read-only mount here fails with `attempt to write a readonly database` (found during Phase 6.1 verification) |

Both paths already exist inside the image, owned by the non-root runtime user, specifically so a
bind mount or named volume onto either "just works" without extra host-side permission changes.

### Providing the model artifact

Train it on the host first (outside Docker, per **ML Detection Pipeline**), then bind-mount the
resulting directory — do not create a fake/synthetic model to satisfy the container.

### Providing the Chroma vector store

Either:
1. Build it on the host first (`uv run python -m backend.rag.ingestion`, per **Build the Vector
   Database**) and bind-mount the resulting `rag/chroma_db/` directory, or
2. Mount an empty/named volume at `/app/rag/chroma_db` and build it *inside* the running
   container: `docker exec <container> python -m backend.rag.ingestion`. The container needs
   outbound internet access the first time, to download the `sentence-transformers/all-MiniLM-L6-v2`
   embedding model from Hugging Face Hub — it is not pre-baked or cached in the image, so the very
   first request that touches retrieval (including `GET /health`) will be slower while it
   downloads, then stays cached in that process's memory for the container's lifetime.

### Connecting to Ollama

The backend never installs or bundles Ollama — it talks to it over HTTP exactly like local dev
does, just with `OLLAMA_HOST` pointed at wherever Ollama actually runs:

```bash
# macOS/Windows Docker Desktop: the host is reachable via this special DNS name
-e OLLAMA_HOST="http://host.docker.internal:11434"

# Linux: host.docker.internal isn't available by default; either run with
# --add-host=host.docker.internal:host-gateway, or point OLLAMA_HOST at the host's
# real LAN/bridge IP.
```

This required zero code changes: the `ollama` Python client already reads `OLLAMA_HOST` from the
environment when constructing its default client (verified by reading `ollama/_client.py` in the
installed package) — `backend/services/llm.py` and `llm_status.py` were untouched in this phase.

### Run

```bash
docker run -d --name cyber-ai-backend \
  -p 8000:8000 \
  -v "$(pwd)/models:/app/models:ro" \
  -v "$(pwd)/rag/chroma_db:/app/rag/chroma_db" \
  -e OLLAMA_HOST="http://host.docker.internal:11434" \
  -e OLLAMA_MODEL="llama3.2:3b" \
  -e CYBER_AI_API_KEY="your-api-key" \
  -e CYBER_AI_USERNAME="your-username" \
  -e CYBER_AI_PASSWORD="your-password" \
  cyber-ai-backend
```

### Health check

```bash
curl http://localhost:8000/health
```

The image also has a built-in `HEALTHCHECK` (`docker ps` shows `healthy`/`unhealthy`) that hits
this same endpoint using the stdlib (no curl/wget installed just for this). `GET /health` never
invokes the LLM — `check_llm_status()` only calls `ollama.list()` (a metadata call), never
`chat()` — so the healthcheck reflects whether the API process itself is up, not whether every
external dependency happens to be perfect. Note: right after a fresh container start, the first
health check or two can be slow (and may transiently report unhealthy under the default 5s
timeout) while the embedding model referenced above finishes its first load — this settles once
that's cached in memory.

### Testing authentication in the container

Identical behavior to local dev — same `require_auth()` code, unmodified:

```bash
# Public, no credentials needed
curl http://localhost:8000/health

# Protected, no credentials -> 401
curl -i -X POST http://localhost:8000/classify -H "Content-Type: application/json" -d '{}'

# Protected, valid API key -> normal behavior
curl -X POST http://localhost:8000/classify \
  -H "Authorization: Bearer your-api-key" -H "Content-Type: application/json" \
  -d '{...78 features...}'
```

### Known limitations

- For running the backend together with the Dockerized frontend, see **Docker Compose** below —
  wiring both up by hand with `docker run` (as shown here) still works, but Compose is simpler.
- The full `pyproject.toml` dependency set is installed as-is (per this phase's scope: no second
  dependency list, no splitting into extras) — this includes notebook-only packages (`jupyter`,
  `matplotlib`, `ipykernel`) and `torch` (pulled in by `sentence-transformers`) that the API itself
  never uses, making the image far larger than a trimmed backend-only dependency set would be.
  Splitting `pyproject.toml` into optional-dependency groups is a reasonable follow-up but wasn't
  done here to stay in scope. Deliberately not optimized in Phase 6.3 either — see **Docker
  Compose** > "Image sizes".
- No persistent Hugging Face cache volume — the embedding model is re-downloaded from the internet
  on every fresh container start (see "Providing the Chroma vector store" above).
- Sessions (Phase 5.2) are in-memory in the FastAPI process, same as local dev: restarting the
  container logs everyone out. Unaffected by containerization, just worth restating here.

## Docker Compose

Phase 6.2 (frontend) and 6.3 (Compose) build on **Docker Backend** above: a second image for the
React frontend, and a `docker-compose.yml` that wires both together. Ollama is deliberately **not**
a Compose service — it keeps running on the host exactly as in every other phase and local dev
(see **Docker Backend** > "Connecting to Ollama" for why).

### Frontend image

```bash
docker build -t cyber-ai-frontend -f frontend/Dockerfile frontend
```

Two stages: a `node:22-alpine` builder runs `npm ci` (installs exactly what `package-lock.json`
pins) then the existing, unmodified `npm run build`; the runtime stage is `nginx:1.27-alpine`
serving only the static build output — no Node.js, no source files, no dev tooling. `nginx.conf`
does one thing: serve static files, with `try_files $uri $uri/ /index.html;` as a fallback so
client-side routes (`/analyze`, `/detection`, `/intelligence`, `/about`, and any other
`react-router-dom` route) work on direct navigation/refresh, not just via in-app links.

**Runtime-configurable backend URL.** A Vite app normally bakes `VITE_API_URL` into the JS bundle
at *build* time, which would mean a separate image per backend URL. Instead this image resolves
the backend URL at *container start*: `frontend/config.template.js` is copied into the image
alongside the build output, and `frontend/docker-entrypoint.sh` renders it into `config.js` (via
`envsubst`, reading the `VITE_API_URL` environment variable) before starting nginx. `index.html`
loads `config.js` before the app bundle, and `src/services/api.ts` reads
`window.__APP_CONFIG__.VITE_API_URL` first, falling back to the build-time
`import.meta.env.VITE_API_URL` (used by `npm run dev`/`npm run build` outside Docker) and then a
hardcoded default. Net effect: the same built image works against any backend by changing one
environment variable in `docker-compose.yml`, no rebuild required. `frontend/public/config.js` is
the static local-dev fallback (`window.__APP_CONFIG__ = {}`) that Vite copies into `dist/` as-is;
Docker overwrites it at container startup.

### Networking

The two containers share a Compose network (`cyber-ai-net`) for isolation, but **the browser talks
to the backend directly** — nginx does not proxy API requests. This was a deliberate choice, not
an oversight: Phase 5.2 already built and verified a complete cross-origin auth flow (CORS
allowlist, `SameSite=None` + `Secure` session cookie, double-submit CSRF cookie), and reusing it
unchanged is simpler and less risky than adding a reverse-proxy layer merely to make the two
containers appear same-origin.

The consequence: the backend's port **must** be published to the host (`8000:8000`), because
`VITE_API_URL` has to be a URL the *browser* (running on the host) can reach — `http://
localhost:8000`, never the Compose service name `http://backend:8000`, which only resolves between
containers on the Docker network, not from the host or the browser. This is the single most common
mistake when Dockerizing a frontend+backend pair together, so it's called out explicitly here.

By default:
- Backend: `http://localhost:8000` (published; also used directly by non-browser API-key clients)
- Frontend: `http://localhost:8080` (nginx, published)

### CORS reconfiguration

This is the one required backend code change in this phase: `CORS_ORIGINS` (`backend/main.py`) is
now a comma-separated environment variable instead of a hardcoded single origin, defaulting to
`http://localhost:5173` (the Vite dev server) so **local dev behavior is completely unchanged**.
`docker-compose.yml` sets it to `http://localhost:5173,http://localhost:8080`, adding the
Dockerized frontend's origin without removing the dev one. No wildcard origins, no wildcard
credentials, and `allow_credentials=True` continues to pair only with an explicit, non-wildcard
allowlist — the same constraint Phase 3 established.

### Volumes

Same two mounts, and the same reasoning, as **Docker Backend** above:

| Path | Mode | Why |
|---|---|---|
| `./models:/app/models` | `:ro` | `joblib.load()` only reads it |
| `./rag/chroma_db:/app/rag/chroma_db` | Read-write | Chroma's SQLite backend needs to write WAL/journal files even for read-only queries (Phase 6.1 finding) — mounting `:ro` breaks every `/analyze` request |

`data/threat_intel/` is **not** a volume — it's baked into the backend image (see **Docker
Backend** > "Build") because `backend/services/knowledge_base.py` reads it at request time, not
just at ingestion time.

### Configuration

```bash
cp .env.example .env
# edit .env with real values -- it is gitignored and must never be committed
docker compose up -d --build
```

`.env.example` documents every variable Compose reads (`CYBER_AI_API_KEY`, `CYBER_AI_USERNAME`,
`CYBER_AI_PASSWORD`, `OLLAMA_HOST`, `OLLAMA_MODEL`, `CORS_ORIGINS`, `VITE_API_URL`) with placeholder
values only. `docker-compose.yml` fails fast (`${VAR:?...}` syntax) if the three auth variables
aren't set, rather than silently starting an effectively-unauthenticated backend.

### Health checks

Both services define a Compose `healthcheck`; `frontend` uses `depends_on: backend: condition:
service_healthy`, so `docker compose up` brings the backend up first. The frontend's healthcheck
(`wget --spider http://127.0.0.1/`) only proves nginx is serving `index.html` — it says nothing
about the backend, Ollama, or the vector store, since nginx never talks to any of them. It targets
`127.0.0.1` explicitly, not `localhost`: the container's `/etc/hosts` resolves `localhost` to
`::1` first, but `nginx.conf` only binds IPv4 (`listen 80;`), so `wget http://localhost/` fails
with "Connection refused" even though the server is up — found live while verifying this phase.

### Testing / live verification performed

- `docker compose config` validates the file; `docker compose up -d --build` brings up both
  containers; both reach and stay `healthy`.
- Browser: loaded `http://localhost:8080`, logged in (`POST /auth/login` succeeds cross-origin,
  `8080` → `8000`, session + CSRF cookies set), landed on the Dashboard with live RAG/LLM status.
- Threat Analysis: submitted "How can DDoS attacks be mitigated?" through the browser against the
  Dockerized backend — real Ollama call, correct `DDOS_ATTACK`/High severity classification, MITRE
  `T1498` (Network Denial of Service), and source attribution to `ddos_attack.txt`.
- Network Detection: the all-zero example classified `BENIGN` (LLM correctly skipped). Separately,
  a real labeled `DDoS` row from the CICIDS2017 dataset was classified via `POST /classify`
  (`prediction: DDoS`, `probability: 1.0`) and chained through `POST /analyze/classification`,
  producing the same MITRE `T1498` report — verifying the full classifier→RAG chain runs correctly
  against the Compose-networked backend.
- Logged out via the browser; confirmed the app drops back to the login gate.
- Direct API-key access to the published backend port still works independently of the browser
  session (`Authorization: Bearer <CYBER_AI_API_KEY>` against `http://localhost:8000`).
- Security: missing/invalid API key → `401` on protected endpoints; public endpoints (`/`,
  `/health`, `/threats`, `/auth/me`) remain reachable with no credentials; a CORS preflight from an
  origin *not* in `CORS_ORIGINS` (`http://evil.example.com`) is rejected (`400`, no
  `Access-Control-Allow-Origin` header); a preflight from `http://localhost:8080` is allowed.
- Confirmed the built frontend JS bundle contains no backend secrets, API keys, or passwords
  (`grep` over `frontend/dist/assets/*.js`).
- A project-wide scan for AI-tool branding/attribution strings (source tree, `frontend/dist/`, and
  both built images' filesystems via `docker run --entrypoint sh ... grep -r`) came back clean.

### Image sizes

| Image | Size |
|---|---|
| `cyber-ai-backend` | ~6.55 GB (unchanged from Phase 6.1 — deliberately not optimized in this phase; see **Docker Backend** > "Known limitations") |
| `cyber-ai-frontend` | ~23 MB (`node:22-alpine` builder is discarded; final image is `nginx:1.27-alpine` + a ~285 KB static build) |

Measured with `docker image inspect <image> --format='{{.Size}}'` (actual on-disk content size,
not `docker images`' larger, misleading "disk usage" column — see **Docker Backend** for the same
caveat).

### Known limitations

- No CI/build pipeline runs any of this automatically (out of scope — see **Known Limitations**
  below).
- No HTTPS/TLS termination for either container; both are plain HTTP, matching every prior phase's
  local-first, localhost-only scope. `Secure` cookies still work because modern browsers treat
  `http://localhost` as a trustworthy origin for that purpose.
- nginx's master process starts as root (standard nginx behavior, needed to bind port 80); its
  worker processes — the ones that actually handle connections — drop to the unprivileged `nginx`
  user built into the base image. This is normal, industry-standard nginx behavior, not a gap
  specific to this image.
- The backend's port is published to the host because the browser needs to reach it directly (see
  **Networking** above) — this is structural to the chosen architecture, not an oversight.

## Testing

```bash
uv run pytest tests/ -v
```

Tests use an isolated, temporary Chroma collection (built fresh each test session from the real
`data/threat_intel/` documents) so they never touch `rag/chroma_db/`. LLM calls are mocked in API
tests, so the suite does **not** require Ollama to be running. Retrieval tests do use the real
embedding model (no network calls — it's cached locally after the first run).

The ML tests likewise never touch `data/raw/` or `models/`: `tests/conftest.py` generates a
small, clearly-synthetic CICIDS-shaped CSV (with a few intentional duplicate rows) and trains a
real — if not meaningful — model artifact against it in an isolated temp directory, purely to
exercise the pipeline's plumbing. **No test result from this fixture is a real accuracy claim.**

Covered:
- Retrieval returns the correct document for each of the 5 threat types
- An off-topic query returns no relevant chunks
- A valid `/analyze` request returns the documented schema
- Empty, whitespace-only, and over-length queries return `422`
- An off-topic query returns `no_relevant_intelligence` **without calling the LLM**
- Vector-store-unavailable, LLM-unavailable, and malformed-LLM-output all return a clean error response instead of crashing
- The classifier model loads, predicts, returns a valid probability, and exposes feature importance
- The synthetic fixture's intentional duplicate rows are removed by `load_and_clean_dataset` (leakage-fix regression test)
- `/classify` handles a valid request, a missing feature, an invalid feature type, an unexpected extra field, and a not-yet-trained model
- `/analyze/classification` maps `DDoS` → a `ddos_attack` RAG analysis, maps `BENIGN` → `analysis: null` **without calling the LLM**, and rejects an unsupported prediction
- API-key auth: missing/invalid/malformed `Authorization` header → `401`; valid key → unchanged behavior; a misconfigured (unset) `CYBER_AI_API_KEY` fails closed rather than crashing or running open
- Session auth: login success/invalid-username/invalid-password/missing-credentials, logout destroys the session, `/auth/me` before and after login, a valid session (+ CSRF header) reaches a protected endpoint, a session without the CSRF header (or with the wrong one) is rejected on state-changing requests
- Security regression checks: the session cookie is `HttpOnly` or the CSRF cookie is deliberately not, no response body ever contains the password/session token/CSRF token, and none of those values (nor the API key) ever appear in captured log output

Frontend automated tests were not added in this phase (no test runner existed for `frontend/`
before it, and adding one — e.g. Vitest + Testing Library — is a separate infrastructure decision
from browser auth integration). The login/logout/redirect flows were verified manually: open the
app signed out, confirm the login page renders, sign in, confirm the app renders and the session
cookie is `HttpOnly` (unreadable from the browser console), sign out, confirm the login page
returns.

## Project Structure

```text
backend/
    main.py               # FastAPI app: /, /health, /threats, /analyze, /classify, /ml/*, /analyze/classification
    models/
        schemas.py         # Pydantic request/response models (RAG)
    rag/
        config.py           # paths + env-driven settings
        embeddings.py        # embedding model loader (cached)
        ingestion.py          # builds/rebuilds the Chroma store from data/threat_intel/
        retrieval.py           # loads the store, relevance-filtered similarity search
    ml/
        config.py            # FEATURE_COLUMNS (single source of truth), paths, hyperparameters
        preprocessing.py      # cleaning shared by train.py and predictor.py
        schemas.py             # dynamically-generated NetworkTrafficFeatures + classification schemas
        train.py                # uv run python -m backend.ml.train -- the only place the model is fit
        predictor.py             # loads the saved model; predict() + feature_importance()
    services/
        llm.py               # Ollama call + structured JSON-schema output + parsing
        llm_status.py         # lightweight Ollama reachability check for /health
        knowledge_base.py     # discovers threat categories for /threats
        threat_analysis.py    # orchestrates retrieval -> MITRE extraction -> LLM -> response
        classification.py     # maps a classifier prediction -> the RAG pipeline above
        auth.py                # login credential validation (backend/sessions.py owns session storage)
    security.py             # require_auth: API key OR session+CSRF, either satisfies protected routes
    sessions.py              # in-memory session store (backend/sessions.py) -- see Authentication
data/threat_intel/         # source threat-intelligence documents
data/raw/                   # CICIDS2017 CSV goes here (gitignored, not committed)
models/                      # trained classifier artifact + metadata (gitignored, not committed)
notebooks/                 # exploratory notebooks (DDoS classifier, RAG pipeline walkthrough)
tests/                      # pytest suite (RAG + ML + auth)
frontend/
    src/
        types/api.ts, ml.ts, auth.ts   # TypeScript types mirroring the backend Pydantic models
        services/api.ts                 # the only fetch() call site; typed, error-normalized, sends cookies
        context/AuthContext.tsx          # auth state; calls GET /auth/me on startup, listens for 401s
        hooks/                            # useHealth, useThreats
        components/
            layout/              # AppShell, Sidebar (incl. logout button)
            common/               # Card, PageHeader, SeverityBadge, StatusPill
            dashboard/            # StatCard
            analysis/             # QueryInput, SampleQueries, LoadingState, AnalysisResult, ...
        pages/                  # LoginPage, DashboardPage, ThreatAnalysisPage, NetworkDetectionPage, ThreatIntelligencePage, AboutPage
        App.tsx                 # router + auth gate
    public/config.js            # local-dev runtime-config fallback (window.__APP_CONFIG__ = {})
    config.template.js          # Docker-only: envsubst template for the same config.js
    docker-entrypoint.sh        # Docker-only: renders config.js from VITE_API_URL, then starts nginx
    nginx.conf                  # Docker-only: static SPA server, no API proxying
    Dockerfile                  # Docker-only: node builder -> nginx:alpine runtime
    .dockerignore
Dockerfile                      # backend image (see Docker Backend)
.dockerignore
docker-compose.yml               # wires the backend + frontend images together (see Docker Compose)
.env.example                     # placeholder values for docker-compose.yml (copy to .env, gitignored)
```

## Known Limitations

- `severity` is a qualitative LLM judgment, not sourced from the knowledge base — the five
  documents contain no severity ratings.
- The LLM occasionally misclassifies which list a grounded fact belongs in (e.g. putting
  mitigation-style text under `indicators` instead of `mitigations`) even though the underlying
  content is always genuinely from the retrieved context. This is a field-mapping quality issue
  with the small local model, not a hallucination/grounding issue.
- Each query reports a single primary threat type; a query that's genuinely about two threats at
  once will only be analyzed with respect to the better-matching one.
- The MITRE ATT&CK coverage is limited to what's written in the five current `.txt` files (one
  or two techniques per file) — it is not a general ATT&CK reference.
- The relevance threshold (`RAG_SCORE_THRESHOLD=1.5`) was tuned against this specific 14-chunk
  knowledge base; it should be re-validated if the corpus grows.
- There is no rate limiting or live threat feed integration.
- The frontend was verified visually at desktop width (~1440px) and functionally end-to-end
  against the real backend + Ollama. Narrower breakpoints (tablet/mobile) are implemented with
  standard Tailwind responsive classes (sidebar collapses to a top bar below `lg`, card grids
  reflow via `sm`/`xl` columns) but were not independently confirmed by resizing a real browser
  viewport in this environment.
- **No real trained classifier model is included or committed.** The actual CICIDS2017 dataset
  was never available in the development environment this project was built in (see "Getting the
  dataset" above) — `/classify` and `/analyze/classification` will return `503` until someone
  runs `uv run python -m backend.ml.train` against the real CSV. The pipeline, leakage fix, API,
  RAG integration, and frontend page were all built and verified against a small synthetic
  fixture (see **Testing**) and a temporary demo dataset used only to visually confirm the UI
  flow — neither represents real-world accuracy, and both were deleted afterward.
- The classifier is binary (BENIGN/DDoS only) and single-threat, same as the original notebook —
  it does not detect other attack types.
- The Random Forest classifier only maps to one RAG query (DDoS → "How can DDoS attacks be
  mitigated?"); this is the same query already proven to retrieve well in **Relevance Filtering**.
