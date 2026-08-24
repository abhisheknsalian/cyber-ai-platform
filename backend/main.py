import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.middleware.cors import CORSMiddleware

from backend.ml.predictor import ModelUnavailableError, feature_importance, model_available, predict
from backend.ml.schemas import (
    ClassificationAnalysisRequest,
    ClassificationAnalysisResponse,
    ClassificationResult,
    FeatureImportanceItem,
    NetworkTrafficFeatures,
)
from backend.models.schemas import (
    AnalyzeRequest,
    AuthStatusResponse,
    HealthResponse,
    LoginRequest,
    ThreatAnalysis,
    ThreatCategory,
)
from backend.rag.config import COLLECTION_NAME
from backend.rag.retrieval import vector_store_available, vector_store_chunk_count
from backend.security import require_auth
from backend.services import auth as auth_service
from backend.services.classification import UnsupportedPredictionError, classify_and_analyze
from backend.services.knowledge_base import list_threat_categories
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.llm_status import check_llm_status
from backend.services.threat_analysis import VectorStoreUnavailableError, analyze_query
from backend.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    is_valid_session,
)

logging.basicConfig(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    if not os.getenv("CYBER_AI_API_KEY"):
        logger.warning(
            "CYBER_AI_API_KEY is not set. The API will still start, but every request "
            "to a protected endpoint (/analyze, /classify, /ml/feature-importance, "
            "/analyze/classification) will be rejected with 401 until it is configured "
            "(or a browser session is used instead -- see /auth/login)."
        )
    if not (os.getenv("CYBER_AI_USERNAME") and os.getenv("CYBER_AI_PASSWORD")):
        logger.warning(
            "CYBER_AI_USERNAME / CYBER_AI_PASSWORD are not both set. POST /auth/login "
            "will reject every attempt until they are configured."
        )
    yield


app = FastAPI(title="Cyber AI Platform", lifespan=lifespan)

# Explicit origin allowlist (Step 12 in Phase 3: no wildcard) -- configurable via
# CORS_ORIGINS (comma-separated) so the Dockerized frontend's origin (e.g.
# http://localhost:8080, see docker-compose.yml) can be added without a code change,
# while the default preserves the exact Phase 3/5.2 local-dev behavior unchanged.
# allow_credentials=True is required for the browser to send/receive the session +
# CSRF cookies cross-origin; it's only safe to combine with a wildcard-free, exact
# allow_origins list, which this always is regardless of how CORS_ORIGINS is set.
_cors_origins = [origin.strip() for origin in os.getenv("CORS_ORIGINS", "http://localhost:5173").split(",") if origin.strip()]
app.add_middleware(
    CORSMiddleware,
    allow_origins=_cors_origins,
    allow_credentials=True,
    allow_methods=["GET", "POST"],
    allow_headers=["Content-Type", "Authorization", "X-CSRF-Token"],
)


def _set_auth_cookies(response: Response, session_token: str, csrf_token: str) -> None:
    # SameSite=None is required because the frontend (localhost:5173) and backend
    # (localhost:8000) are different origins -- Lax/Strict cookies are simply never
    # sent on that cross-origin fetch. Secure=True is required to pair with
    # SameSite=None; modern browsers treat http://localhost as a trustworthy origin
    # for this purpose, so it still works without HTTPS in local dev.
    response.set_cookie(
        key=SESSION_COOKIE_NAME,
        value=session_token,
        httponly=True,
        secure=True,
        samesite="none",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )
    # Deliberately NOT HttpOnly: the frontend must be able to read this one to echo
    # it back as the X-CSRF-Token header (double-submit pattern).
    response.set_cookie(
        key=CSRF_COOKIE_NAME,
        value=csrf_token,
        httponly=False,
        secure=True,
        samesite="none",
        max_age=SESSION_TTL_SECONDS,
        path="/",
    )


def _clear_auth_cookies(response: Response) -> None:
    response.delete_cookie(SESSION_COOKIE_NAME, path="/")
    response.delete_cookie(CSRF_COOKIE_NAME, path="/")


@app.get("/")
def home():
    return {"message": "Cyber AI Platform Running"}


@app.post("/auth/login", response_model=AuthStatusResponse)
def login(payload: LoginRequest, response: Response) -> AuthStatusResponse:
    """Browser session login. Public. Never logs or echoes the password."""
    try:
        session_token, csrf_token = auth_service.login(payload.username, payload.password)
    except auth_service.InvalidCredentialsError:
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    except Exception:
        logger.exception("Unexpected error during login")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while logging in.")

    _set_auth_cookies(response, session_token, csrf_token)
    return AuthStatusResponse(authenticated=True, username=payload.username)


@app.post("/auth/logout", response_model=AuthStatusResponse)
def logout(request: Request, response: Response) -> AuthStatusResponse:
    """Destroys the current session, if any. Public and idempotent -- calling it
    with no session (or an already-expired one) still succeeds."""
    auth_service.logout(request.cookies.get(SESSION_COOKIE_NAME))
    _clear_auth_cookies(response)
    return AuthStatusResponse(authenticated=False)


@app.get("/auth/me", response_model=AuthStatusResponse)
def me(request: Request) -> AuthStatusResponse:
    """Reports whether the current browser session is authenticated. Public --
    this is how the frontend asks "am I logged in?" without ever erroring."""
    authenticated = is_valid_session(request.cookies.get(SESSION_COOKIE_NAME))
    return AuthStatusResponse(authenticated=authenticated, username=os.getenv("CYBER_AI_USERNAME") if authenticated else None)


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
def analyze_threat(request: AnalyzeRequest, _: None = Depends(require_auth)) -> ThreatAnalysis:
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
def classify_traffic(features: NetworkTrafficFeatures, _: None = Depends(require_auth)) -> ClassificationResult:
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
def ml_feature_importance(top_n: int = 15, _: None = Depends(require_auth)) -> list[FeatureImportanceItem]:
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
    request: ClassificationAnalysisRequest, _: None = Depends(require_auth)
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
