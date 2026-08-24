import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware

from backend.ml.predictor import ModelUnavailableError, feature_importance, model_available, predict
from backend.ml.schemas import (
    ClassificationAnalysisRequest,
    ClassificationAnalysisResponse,
    ClassificationResult,
    FeatureImportanceItem,
    NetworkTrafficFeatures,
)
from backend.models.schemas import AnalyzeRequest, HealthResponse, ThreatAnalysis, ThreatCategory
from backend.rag.config import COLLECTION_NAME
from backend.rag.retrieval import vector_store_available, vector_store_chunk_count
from backend.security import require_api_key
from backend.services.classification import UnsupportedPredictionError, classify_and_analyze
from backend.services.knowledge_base import list_threat_categories
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.llm_status import check_llm_status
from backend.services.threat_analysis import VectorStoreUnavailableError, analyze_query

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.getenv("CYBER_AI_API_KEY"):
        logger.warning(
            "CYBER_AI_API_KEY is not set. The API will still start, but every request "
            "to a protected endpoint (/analyze, /classify, /ml/feature-importance, "
            "/analyze/classification) will be rejected with 401 until it is configured."
        )
    yield


app = FastAPI(title="Cyber AI Platform", lifespan=lifespan)

# Explicit dev origin for the Vite frontend (Step 12: no wildcard).
app.add_middleware(
    CORSMiddleware,
    allow_origins=["http://localhost:5173"],
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization"],
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
def analyze_threat(request: AnalyzeRequest, _: None = Depends(require_api_key)) -> ThreatAnalysis:
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


@app.post("/classify", response_model=ClassificationResult)
def classify_traffic(features: NetworkTrafficFeatures, _: None = Depends(require_api_key)) -> ClassificationResult:
    """CICIDS2017-based DDoS/BENIGN traffic classification (Random Forest).

    Not a general-purpose malware detector and not a live network monitor -- this
    scores a single already-extracted CICFlowMeter feature vector offline.
    """
    if not model_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "No trained classifier found. Train one first with: "
                "uv run python -m backend.ml.train"
            ),
        )
    try:
        return predict(features)
    except ModelUnavailableError:
        raise HTTPException(
            status_code=503,
            detail=(
                "No trained classifier found. Train one first with: "
                "uv run python -m backend.ml.train"
            ),
        )
    except Exception:
        logger.exception("Unexpected error during classification")
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while classifying the traffic sample.",
        )


@app.get("/ml/feature-importance", response_model=list[FeatureImportanceItem])
def ml_feature_importance(top_n: int = 15, _: None = Depends(require_api_key)) -> list[FeatureImportanceItem]:
    """Top features by the trained Random Forest's own feature_importances_."""
    if not model_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "No trained classifier found. Train one first with: "
                "uv run python -m backend.ml.train"
            ),
        )
    return feature_importance(top_n=top_n)


@app.post("/analyze/classification", response_model=ClassificationAnalysisResponse)
def analyze_classification(
    request: ClassificationAnalysisRequest, _: None = Depends(require_api_key)
) -> ClassificationAnalysisResponse:
    """Take an already-computed classifier prediction (e.g. from POST /classify) and,
    if it's a threat, run it through the same RAG pipeline as /analyze. This does not
    re-run the classifier -- it only maps a given prediction to a threat report.
    """
    try:
        classification, analysis = classify_and_analyze(request)
        return ClassificationAnalysisResponse(classification=classification, analysis=analysis)
    except UnsupportedPredictionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
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
        logger.exception("Unexpected error while analyzing classification: %r", request)
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while analyzing the classification.",
        )
