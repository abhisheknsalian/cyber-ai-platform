import logging
import os
from contextlib import asynccontextmanager

from fastapi import Depends, FastAPI, HTTPException, Request, Response
from fastapi.encoders import jsonable_encoder
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.config_validation import ConfigurationError, validate_startup_config
from backend.intelligence.graph_store import get_graph
from backend.intelligence.hybrid_retrieval import gather_hybrid_evidence, graph_neighborhood
from backend.intelligence.schemas import (
    EntitySummary,
    GraphEvidenceItem,
    IntelligenceSearchRequest,
    IntelligenceSearchResult,
    ThreatGraphNeighborhood,
)
from backend.logging_config import configure_logging
from backend.middleware import RequestContextMiddleware, SecurityHeadersMiddleware
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
    ReadinessChecks,
    ReadinessResponse,
    RegisterRequest,
    ThreatAnalysis,
    ThreatCategory,
    UserPublicResponse,
)
from backend.rag.config import COLLECTION_NAME
from backend.rag.retrieval import vector_store_available, vector_store_chunk_count
from backend.rate_limit import enforce_ai_rate_limit, enforce_login_rate_limit
from backend.security import require_auth
from backend.services import auth as auth_service
from backend.services import users as users_service
from backend.services.classification import UnsupportedPredictionError, classify_and_analyze
from backend.services.knowledge_base import list_threat_categories
from backend.services.llm import LLMResponseError, LLMUnavailableError
from backend.services.llm_status import check_llm_status
from backend.services.threat_analysis import VectorStoreUnavailableError, analyze_query
from backend.sessions import (
    CSRF_COOKIE_NAME,
    SESSION_COOKIE_NAME,
    SESSION_TTL_SECONDS,
    session_identity,
)

configure_logging(level=logging.INFO)
logger = logging.getLogger(__name__)


@asynccontextmanager
async def lifespan(app: FastAPI):
    try:
        validate_startup_config()
    except ConfigurationError as exc:
        # Fails startup outright for a malformed *non-secret* setting -- unlike the
        # two warnings below, this can't be "fixed later while the app keeps serving
        # public endpoints", because e.g. a CORS_ORIGINS containing '*' combined with
        # allow_credentials=True is a real misconfiguration, not a deferred choice.
        logger.error("Startup configuration invalid: %s", exc, extra={"event": "config_invalid"})
        raise

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
    logger.info("Cyber AI Platform starting up", extra={"event": "startup"})
    yield
    logger.info("Cyber AI Platform shutting down", extra={"event": "shutdown"})


app = FastAPI(title="Cyber AI Platform", lifespan=lifespan)

# Order matters: Starlette executes middleware outer-to-inner in *reverse* of
# add_middleware() call order, so the last one added runs first/outermost. Security
# headers should wrap everything (including error responses), and request-ID/timing
# should be the very outermost so it captures the full request lifecycle -- so it's
# added last.
app.add_middleware(SecurityHeadersMiddleware)
app.add_middleware(RequestContextMiddleware)

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


@app.post("/auth/register", response_model=UserPublicResponse, status_code=201)
def register(
    payload: RegisterRequest,
    _: None = Depends(enforce_login_rate_limit),
) -> UserPublicResponse:
    """Create a new persistent user account. Public, rate-limited by the same
    per-IP budget as /auth/login (RATE_LIMIT_LOGIN_MAX) -- both are unauthenticated
    endpoints that touch the password-hashing path, the same abuse surface, so they
    share one budget rather than doubling a caller's effective quota by splitting it
    across two endpoints (same reasoning AI_RATE_LIMIT already applies to /analyze,
    /classify, /analyze/classification). Does not log the user in -- see README
    "Authentication" for the registration flow.
    """
    try:
        user = auth_service.register(payload.username, payload.password)
    except users_service.InvalidRegistrationError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except users_service.UsernameTakenError as exc:
        raise HTTPException(status_code=409, detail=str(exc))
    except Exception:
        logger.exception("Unexpected error during registration")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while registering.")

    logger.info("Registration succeeded", extra={"event": "register_success"})
    return UserPublicResponse(id=user.id, username=user.username, created_at=user.created_at)


@app.post("/auth/login", response_model=AuthStatusResponse)
def login(
    payload: LoginRequest,
    response: Response,
    _: None = Depends(enforce_login_rate_limit),
) -> AuthStatusResponse:
    """Browser session login. Public (rate-limited by IP). Never logs or echoes the
    username or password -- only whether the attempt succeeded. Accepts either a
    registered account or the demo/bootstrap credentials -- see
    backend/services/auth.py for how the two are tried and kept separate."""
    try:
        session_token, csrf_token, user_id, username = auth_service.login(payload.username, payload.password)
    except auth_service.InvalidCredentialsError:
        logger.warning("Login failed", extra={"event": "login_failure"})
        raise HTTPException(status_code=401, detail="Invalid username or password.")
    except Exception:
        logger.exception("Unexpected error during login")
        raise HTTPException(status_code=500, detail="An unexpected error occurred while logging in.")

    logger.info("Login succeeded", extra={"event": "login_success"})
    _set_auth_cookies(response, session_token, csrf_token)
    return AuthStatusResponse(authenticated=True, username=username, user_id=user_id)


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
    identity = session_identity(request.cookies.get(SESSION_COOKIE_NAME))
    if identity is None:
        return AuthStatusResponse(authenticated=False)
    user_id, username = identity
    return AuthStatusResponse(authenticated=True, username=username, user_id=user_id)


@app.get("/health", response_model=HealthResponse)
def health() -> HealthResponse:
    """Process/application health -- always 200 while the process is up and able to
    handle a request, regardless of whether Ollama/the vector store/the classifier
    happen to be ready. Reports their status for visibility but never fails or blocks
    on them, and never runs LLM inference. This is the process *liveness* signal (see
    README "Health vs Readiness"); for whether protected functionality can actually
    be served, use GET /ready instead. Unchanged response shape from Phase 6 -- kept
    stable for existing clients."""
    return HealthResponse(
        status="ok",
        vector_store=dict(
            available=vector_store_available(),
            chunk_count=vector_store_chunk_count(),
            collection=COLLECTION_NAME,
        ),
        llm=check_llm_status(),
    )


@app.get("/ready", response_model=ReadinessResponse)
def ready(response: Response) -> ReadinessResponse:
    """Readiness: whether the runtime dependencies required for the protected AI
    endpoints (RAG, classifier, LLM) are actually available right now. Distinct from
    GET /health (see above) -- this can and does return 503 when e.g. Ollama isn't
    running or no model has been trained yet, which /health deliberately never does.
    Like /health, this never runs LLM generation -- check_llm_status() only calls
    ollama.list() (metadata), and model_available()/vector_store_available() are
    cheap existence checks, so this stays fast and doesn't slow down startup probes.
    """
    checks = ReadinessChecks(
        vector_store=vector_store_available(),
        llm=check_llm_status().reachable,
        classifier=model_available(),
    )
    is_ready = checks.vector_store and checks.llm and checks.classifier
    response.status_code = 200 if is_ready else 503
    return ReadinessResponse(ready=is_ready, checks=checks)


@app.get("/threats", response_model=list[ThreatCategory])
def threats() -> list[ThreatCategory]:
    """Threat categories actually present in data/threat_intel/, for the frontend."""
    return list_threat_categories()


@app.get("/intelligence/entities", response_model=list[EntitySummary])
def intelligence_entities(entity_type: str | None = None) -> list[EntitySummary]:
    """Every entity in the threat-intelligence graph (Phase 9), optionally filtered
    to one entity type (threat/technique/indicator/mitigation/source). Public and
    read-only, like GET /threats -- this is knowledge-base metadata derived
    deterministically from data/threat_intel/*.txt, not a protected or expensive AI
    operation, so it follows /threats' convention rather than /analyze's."""
    entities = get_graph().entities.values()
    if entity_type is not None:
        entities = [e for e in entities if e.type == entity_type]
    return [EntitySummary(id=e.id, type=e.type, name=e.name) for e in entities]


@app.get("/intelligence/graph/{threat_id}", response_model=ThreatGraphNeighborhood)
def intelligence_graph(threat_id: str) -> ThreatGraphNeighborhood:
    """One threat's direct graph relationships (Phase 9) -- e.g. threat_id=
    "ddos_attack" returns the DDoS Attack entity plus its USES/HAS_INDICATOR/
    MITIGATED_BY/SUPPORTED_BY edges. Public, like GET /threats. Takes the plain
    filename stem (e.g. "ddos_attack"), not the "threat:ddos_attack" internal ID --
    matching /threats' `threat_type` field so the frontend can link the two directly.
    """
    neighborhood = graph_neighborhood(threat_id)
    if neighborhood is None:
        raise HTTPException(status_code=404, detail=f"No threat entity found for {threat_id!r}.")
    return neighborhood


@app.post("/intelligence/search", response_model=list[IntelligenceSearchResult])
def intelligence_search(
    request: IntelligenceSearchRequest,
    _: None = Depends(enforce_ai_rate_limit),
    __: None = Depends(require_auth),
) -> list[IntelligenceSearchResult]:
    """Hybrid search (Phase 9): vector-relevant chunks, each enriched with its own
    threat's direct graph relationships. Protected + rate-limited like /analyze (not
    public like the two endpoints above) because, like /analyze, it runs a real
    embedding similarity search per request."""
    if not vector_store_available():
        raise HTTPException(
            status_code=503,
            detail=(
                "Vector store not found. Build it first with: "
                "uv run python -m backend.rag.ingestion"
            ),
        )
    try:
        evidence = gather_hybrid_evidence(request.query)
    except Exception:
        logger.exception("Unexpected error during intelligence search", extra={"event": "intelligence_search_error"})
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while searching.",
        )

    results: list[IntelligenceSearchResult] = []
    for item in evidence.vector_evidence:
        # Graph evidence in `evidence` above is only computed for the single overall
        # "primary" threat -- for a genuinely mixed-topic result set, each row here
        # looks up its own threat_type's relations directly rather than reusing that.
        neighborhood = graph_neighborhood(item.threat_type)
        graph_relations = (
            [
                GraphEvidenceItem(
                    relation=relation.relation,
                    target_id=relation.target.id,
                    target_name=relation.target.name,
                    target_type=relation.target.type,
                    reference=relation.reference,
                )
                for relation in neighborhood.relations
            ]
            if neighborhood is not None
            else []
        )
        results.append(
            IntelligenceSearchResult(
                source=item.source,
                threat_type=item.threat_type,
                chunk_index=item.chunk_index,
                score=item.score,
                graph_relations=graph_relations,
            )
        )
    return results


@app.post("/analyze", response_model=ThreatAnalysis)
def analyze_threat(
    request: AnalyzeRequest,
    _: None = Depends(enforce_ai_rate_limit),
    __: None = Depends(require_auth),
) -> ThreatAnalysis:
    try:
        return analyze_query(request.query)
    except VectorStoreUnavailableError:
        logger.warning("Vector store unavailable", extra={"event": "vector_store_unavailable"})
        raise HTTPException(
            status_code=503,
            detail=(
                "Vector store not found. Build it first with: "
                "uv run python -m backend.rag.ingestion"
            ),
        )
    except LLMUnavailableError:
        logger.warning("LLM unavailable", extra={"event": "llm_unavailable"})
        raise HTTPException(
            status_code=503,
            detail=(
                "The local LLM (Ollama) is unavailable. Ensure 'ollama serve' is "
                "running and the configured model has been pulled."
            ),
        )
    except LLMResponseError:
        logger.warning("LLM response failed schema validation", extra={"event": "llm_response_invalid"})
        raise HTTPException(
            status_code=502,
            detail="The LLM returned a response that could not be parsed into a valid analysis.",
        )
    except Exception:
        logger.exception("Unexpected error while analyzing query", extra={"event": "analyze_error"})
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while analyzing the query.",
        )


@app.post("/classify", response_model=ClassificationResult)
def classify_traffic(
    features: NetworkTrafficFeatures,
    _: None = Depends(enforce_ai_rate_limit),
    __: None = Depends(require_auth),
) -> ClassificationResult:
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
        logger.warning("Classifier unavailable", extra={"event": "classifier_unavailable"})
        raise HTTPException(
            status_code=503,
            detail=(
                "No trained classifier found. Train one first with: "
                "uv run python -m backend.ml.train"
            ),
        )
    except Exception:
        logger.exception("Unexpected error during classification", extra={"event": "classify_error"})
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
    request: ClassificationAnalysisRequest,
    _: None = Depends(enforce_ai_rate_limit),
    __: None = Depends(require_auth),
) -> ClassificationAnalysisResponse:
    """Take an already-computed classifier prediction (e.g. from POST /classify) and,
    if it's a threat, run it through the same RAG pipeline as /analyze. This does not
    re-run the classifier -- it only maps a given prediction to a threat report.
    """
    try:
        classification, analysis, evidence = classify_and_analyze(request)
        return ClassificationAnalysisResponse(classification=classification, analysis=analysis, evidence=evidence)
    except UnsupportedPredictionError as exc:
        raise HTTPException(status_code=422, detail=str(exc))
    except VectorStoreUnavailableError:
        logger.warning("Vector store unavailable", extra={"event": "vector_store_unavailable"})
        raise HTTPException(
            status_code=503,
            detail=(
                "Vector store not found. Build it first with: "
                "uv run python -m backend.rag.ingestion"
            ),
        )
    except LLMUnavailableError:
        logger.warning("LLM unavailable", extra={"event": "llm_unavailable"})
        raise HTTPException(
            status_code=503,
            detail=(
                "The local LLM (Ollama) is unavailable. Ensure 'ollama serve' is "
                "running and the configured model has been pulled."
            ),
        )
    except LLMResponseError:
        logger.warning("LLM response failed schema validation", extra={"event": "llm_response_invalid"})
        raise HTTPException(
            status_code=502,
            detail="The LLM returned a response that could not be parsed into a valid analysis.",
        )
    except Exception:
        logger.exception("Unexpected error while analyzing classification", extra={"event": "analyze_classification_error"})
        raise HTTPException(
            status_code=500,
            detail="An unexpected error occurred while analyzing the classification.",
        )


# --- Error response envelope -------------------------------------------------
#
# All three handlers below add a `request_id` field alongside the existing `detail`
# field, purely additively -- `detail`'s shape (a string for HTTPException, a list of
# {loc, msg, ...} for validation errors) is unchanged, so frontend/src/services/api.ts
# (which branches on typeof body.detail) keeps working without modification. Nothing
# here changes a status code that was already being returned.
#
# Reads the ID from request.state (set by RequestContextMiddleware before call_next),
# not the get_request_id() contextvar: registering a handler for the base Exception
# class makes Starlette treat it as ServerErrorMiddleware's handler, which sits
# OUTSIDE every user middleware (including RequestContextMiddleware) -- by the time it
# runs, that middleware's own `finally: reset_request_id(...)` has already fired, so
# the contextvar would already be back to its previous value. request.state isn't
# contextvar-based and isn't affected by that reset.


def _request_id_of(request: Request) -> str | None:
    return getattr(request.state, "request_id", None)


@app.exception_handler(HTTPException)
async def _http_exception_handler(request: Request, exc: HTTPException) -> JSONResponse:
    return JSONResponse(
        status_code=exc.status_code,
        content={"detail": exc.detail, "request_id": _request_id_of(request)},
        headers=exc.headers,
    )


@app.exception_handler(RequestValidationError)
async def _validation_exception_handler(request: Request, exc: RequestValidationError) -> JSONResponse:
    # jsonable_encoder is required here (matching FastAPI's own default handler):
    # exc.errors() can include a `ctx` field carrying the raw exception object from a
    # custom @field_validator (e.g. AnalyzeRequest.not_blank's ValueError), which
    # isn't JSON-serializable on its own.
    return JSONResponse(
        status_code=422,
        content={"detail": jsonable_encoder(exc.errors()), "request_id": _request_id_of(request)},
    )


@app.exception_handler(Exception)
async def _unhandled_exception_handler(request: Request, exc: Exception) -> JSONResponse:
    # Safety net for any route with no explicit try/except (e.g. GET /threats,
    # GET /ml/feature-importance) or a genuinely unexpected bug elsewhere. Full
    # traceback goes to the server log only -- filesystem paths, Python internals, and
    # environment details never reach the HTTP response.
    logger.exception("Unhandled exception", extra={"event": "unhandled_exception", "path": request.url.path})
    return JSONResponse(
        status_code=500,
        content={"detail": "An unexpected error occurred.", "request_id": _request_id_of(request)},
    )
