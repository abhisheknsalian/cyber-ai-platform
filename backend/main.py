import logging

from fastapi import FastAPI, HTTPException

from backend.models.schemas import AnalyzeRequest, ThreatAnalysis
from backend.rag.retrieval import vector_store_available
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.threat_analysis import VectorStoreUnavailableError, analyze_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)

app = FastAPI(title="Cyber AI Platform")


@app.get("/")
def home():
    return {"message": "Cyber AI Platform Running"}


@app.get("/health")
def health():
    return {
        "status": "ok",
        "vector_store_available": vector_store_available(),
    }


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
