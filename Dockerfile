# syntax=docker/dockerfile:1
#
# Production-style image for the FastAPI backend ONLY (Phase 6.1). The frontend,
# Ollama, the trained Random Forest model, the CICIDS2017 dataset, and the Chroma
# vector store are all intentionally NOT part of this image -- see the README
# "Docker Backend" section for how each is supplied at runtime.
#
# Two stages:
#   1. builder  -- resolves/installs the existing pyproject.toml/uv.lock dependency
#      set with uv, reproducibly (`--frozen`). No second dependency list is created.
#   2. runtime  -- a fresh, minimal image containing only the installed virtualenv
#      plus the application source actually needed at runtime (backend/ and
#      data/threat_intel/). No uv, no compilers, no dev/test tooling.

FROM python:3.12-slim AS builder

# Official Astral-published static uv binary -- not the app's runtime environment,
# just a build tool, so this stage never appears in the final image.
COPY --from=ghcr.io/astral-sh/uv:0.9 /uv /uvx /bin/

# UV_HTTP_TIMEOUT: uv's default (~30s) is too short for the several-hundred-MB
# NVIDIA/CUDA wheels pulled in transitively via torch <- sentence-transformers on a
# slower connection, causing `uv sync` below to fail with a download timeout even
# though the locked dependency set itself is unchanged. This only raises how long uv
# waits per HTTP operation during this build step -- it does not change what gets
# installed, add/remove any dependency, or affect the running application.
ENV UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    UV_PYTHON_DOWNLOADS=never \
    UV_HTTP_TIMEOUT=300

WORKDIR /app

# Only the lockfile + project metadata are needed to resolve dependencies, so this
# layer only invalidates when a dependency actually changes -- not on every code
# edit. --no-dev excludes the pytest dev-group (not needed to run the API).
# --no-install-project: the local "cyber-ai-platform" package is never pip-installed
# anywhere (not even in local dev, which runs `uv run uvicorn backend.main:app` from
# the project root) -- only its third-party dependencies need to land in the venv.
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project


FROM python:3.12-slim AS runtime

# Non-root runtime user (Docker requirement 12).
RUN groupadd --system app \
    && useradd --system --gid app --home-dir /app --no-create-home appuser

WORKDIR /app

ENV PATH="/app/.venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    PYTHONPATH=/app

# The installed virtualenv from the builder stage -- no uv, no build tooling, no
# pip cache carried into the final image.
COPY --from=builder /app/.venv /app/.venv

# Only the application code and the one runtime data dependency actually read by the
# backend (backend/services/knowledge_base.py and threat_analysis.py's MITRE
# extraction both read data/threat_intel/*.txt directly at request time -- this is
# not just an ingestion-time asset). Deliberately NOT `COPY . .`.
COPY backend/ backend/
COPY data/threat_intel/ data/threat_intel/

# Mount points for the two gitignored runtime artifacts this image never contains:
# the trained classifier (models/) and the Chroma vector store (rag/chroma_db/).
# Created here (and chowned) so a bind mount or named volume onto either path works
# for the non-root user without extra host-side permission fiddling.
RUN mkdir -p /app/models /app/rag/chroma_db \
    && chown -R appuser:app /app

USER appuser

EXPOSE 8000

# GET /health never invokes the LLM (backend/services/llm_status.py only calls
# ollama.list(), a metadata call, not generation) -- so this healthcheck reports
# whether the API process itself is up, not whether Ollama/the model/the vector
# store happen to be ready. Uses the stdlib instead of curl/wget to avoid adding a
# package just for this.
HEALTHCHECK --interval=30s --timeout=5s --start-period=15s --retries=3 \
    CMD python -c "import urllib.request,sys; sys.exit(0 if urllib.request.urlopen('http://localhost:8000/health', timeout=3).status==200 else 1)"

# Production server: no --reload, binds all interfaces so the container's port
# mapping works.
CMD ["python", "-m", "uvicorn", "backend.main:app", "--host", "0.0.0.0", "--port", "8000"]
