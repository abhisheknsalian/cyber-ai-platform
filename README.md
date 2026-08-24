# Cyber AI Platform

A local, retrieval-augmented cybersecurity threat-intelligence analysis platform: a React
dashboard backed by a FastAPI service. The backend embeds a small knowledge base of threat
write-ups (`data/threat_intel/*.txt`) into a Chroma vector store and uses a locally-running
Llama 3.2 model (via [Ollama](https://ollama.com)) to turn a natural-language question into a
**validated, structured JSON threat analysis** with source attribution.

## Architecture

```text
React dashboard (Vite + TypeScript + Tailwind)
   → FastAPI (POST /analyze, GET /health, GET /threats)
   → relevance-filtered retrieval (ChromaDB + HuggingFace embeddings)
   → deterministic threat-type identification + MITRE ATT&CK extraction (from source docs)
   → structured LLM generation (Ollama / Llama 3.2, JSON-schema constrained)
   → validated Pydantic response with source attribution
   → React
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
uv run uvicorn backend.main:app --reload
```

`uv sync` installs FastAPI, LangChain, ChromaDB, sentence-transformers, the Ollama client,
pytest, and the existing notebook/ML dependencies into a local `.venv`.

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
- **Threat Intelligence** (`/intelligence`) — the threat categories from `GET /threats`, i.e.
  exactly what's in `data/threat_intel/`.
- **About** (`/about`) — architecture explanation; states plainly what is and isn't implemented.

**API integration**: `frontend/src/services/api.ts` is the only place that calls `fetch`;
`analyzeThreat`/`getHealth`/`getThreats` are typed against `frontend/src/types/api.ts`, which
mirrors `backend/models/schemas.py` field-for-field. Requests time out after 60s. Every failure
mode (backend unreachable, timeout, non-2xx, malformed JSON) is normalized into a single
`ApiError` with a user-facing message — no raw errors or stack traces reach the UI.

**Configuration**: the backend URL is read from `VITE_API_URL` (see `frontend/.env.example`),
defaulting to `http://localhost:8000` if unset. Never commit `frontend/.env`.

**CORS**: the backend explicitly allows `http://localhost:5173` (the Vite dev server) via
`CORSMiddleware` in `backend/main.py` — not a wildcard.

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

## Testing

```bash
uv run pytest tests/ -v
```

Tests use an isolated, temporary Chroma collection (built fresh each test session from the real
`data/threat_intel/` documents) so they never touch `rag/chroma_db/`. LLM calls are mocked in API
tests, so the suite does **not** require Ollama to be running. Retrieval tests do use the real
embedding model (no network calls — it's cached locally after the first run).

Covered:
- Retrieval returns the correct document for each of the 5 threat types
- An off-topic query returns no relevant chunks
- A valid `/analyze` request returns the documented schema
- Empty, whitespace-only, and over-length queries return `422`
- An off-topic query returns `no_relevant_intelligence` **without calling the LLM**
- Vector-store-unavailable, LLM-unavailable, and malformed-LLM-output all return a clean error response instead of crashing

## Project Structure

```text
backend/
    main.py               # FastAPI app: /, /health, /threats, /analyze
    models/
        schemas.py         # Pydantic request/response models
    rag/
        config.py           # paths + env-driven settings
        embeddings.py        # embedding model loader (cached)
        ingestion.py          # builds/rebuilds the Chroma store from data/threat_intel/
        retrieval.py           # loads the store, relevance-filtered similarity search
    services/
        llm.py               # Ollama call + structured JSON-schema output + parsing
        llm_status.py         # lightweight Ollama reachability check for /health
        knowledge_base.py     # discovers threat categories for /threats
        threat_analysis.py    # orchestrates retrieval -> MITRE extraction -> LLM -> response
data/threat_intel/         # source threat-intelligence documents
notebooks/                 # exploratory notebooks (DDoS classifier, RAG pipeline walkthrough)
tests/                      # pytest suite (retrieval + API)
frontend/
    src/
        types/api.ts         # TypeScript types mirroring backend/models/schemas.py
        services/api.ts       # the only fetch() call site; typed, error-normalized
        hooks/                 # useHealth, useThreats
        components/
            layout/              # AppShell, Sidebar
            common/               # Card, PageHeader, SeverityBadge, StatusPill
            dashboard/            # StatCard
            analysis/             # QueryInput, SampleQueries, LoadingState, AnalysisResult, ...
        pages/                  # DashboardPage, ThreatAnalysisPage, ThreatIntelligencePage, AboutPage
        App.tsx                 # router
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
- The Random Forest DDoS traffic classifier in `notebooks/01_data_exploration.ipynb` is a
  separate, unintegrated experiment — it is not wired into `/analyze`.
- There is no authentication, rate limiting, live threat feeds, or Docker/deployment setup yet.
- The frontend was verified visually at desktop width (~1440px) and functionally end-to-end
  against the real backend + Ollama. Narrower breakpoints (tablet/mobile) are implemented with
  standard Tailwind responsive classes (sidebar collapses to a top bar below `lg`, card grids
  reflow via `sm`/`xl` columns) but were not independently confirmed by resizing a real browser
  viewport in this environment.
