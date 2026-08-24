import logging

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.models.schemas import AnalyzeRequest, HealthResponse, ThreatAnalysis, ThreatCategory
from backend.rag.config import COLLECTION_NAME
from backend.rag.retrieval import vector_store_available, vector_store_chunk_count
from backend.services.knowledge_base import list_threat_categories
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.llm_status import check_llm_status
from backend.services.threat_analysis import VectorStoreUnavailableError, analyze_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Cyber AI Platform")

# Explicit dev origin for the Vite frontend (Step 12: no wildcard).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type"],
)


@app.get("/")
def home():
    return {"message": "Cyber AI Platform Running"}


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Reports API/vector-store/LLM status. Does not run any LLM inference."""
    return HealthResponse(
        status="ok",
        vector_store=dict(
            available=vector_store_available(),
            chunk_count=vector_store_chunk_count(),
            collection=COLLECTION_NAME,
        ),
        llm=check_llm_status(),
    )


@app.get("/threats", response_model=list[ThreatCategory])
def threats() -> list[ThreatCategory]:
    """Threat categories actually present in data/threat_intel/, for the frontend."""
    return list_threat_categories()


@app.post("/analyze", response_model=ThreatAnalysis)
def analyze_threat(request: AnalyzeRequest) -> ThreatAnalysis:
    try:
        return analyze_query(request.query)
    except VectorStoreUnavailableError:
        raise HTTPException(
            status_code=503,
            detail=(
                "Vector store not found. Build it first with: "
                "uv run python -m backend.rag.ingestion"
            ),
        )
    except LLMUnavailableError:
        raise HTTPException(
            status_code=503,
            detail=(
                "The local LLM (Ollama) is unavailable. Ensure 'ollama serve' is "
                "running and the configured model has been pulled."
            ),
        )
    except LLMResponseError:
        raise HTTPException(
            status_code=502,
            detail="The LLM returned a response that could not be parsed into a valid analysis.",
        )
    except Exception:
        logger.exception("Unexpected error while analyzing query: %r", request.query)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while analyzing the query.",
        )
