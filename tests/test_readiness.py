"""Tests for GET /health (unchanged contract) and the new GET /ready (Phase 8)."""

from unittest.mock import patch

import pytest
from fastapi.testclient import TestClient

from backend.main import app
from backend.security import require_auth


@pytest.fixture(autouse=True)
def _bypass_auth():
    app.dependency_overrides[require_auth] = lambda: None
    yield
    app.dependency_overrides.pop(require_auth, None)


client = TestClient(app)


def test_health_is_public_and_always_200():
    response = client.get("/health")
    assert response.status_code == 200


def test_health_response_shape_is_unchanged():
    # Existing clients (the frontend's useHealth hook) depend on exactly this shape --
    # Phase 8 must not break it.
    body = client.get("/health").json()
    assert set(body.keys()) == {"status", "vector_store", "llm"}
    assert set(body["vector_store"].keys()) == {"available", "chunk_count", "collection"}
    assert set(body["llm"].keys()) == {"model", "reachable", "model_pulled"}


def test_health_never_reflects_dependency_failure_in_status_code():
    # /health is a liveness signal, not a readiness signal -- it stays 200 even when
    # every dependency is down, by design (see README "Health vs Readiness").
    with (
        patch("backend.main.vector_store_available", return_value=False),
        patch("backend.main.check_llm_status") as mocked_llm,
    ):
        from backend.models.schemas import LLMStatus

        mocked_llm.return_value = LLMStatus(model="llama3.2:3b", reachable=False, model_pulled=False)
        response = client.get("/health")
    assert response.status_code == 200


def test_ready_returns_200_when_all_dependencies_available():
    with (
        patch("backend.main.vector_store_available", return_value=True),
        patch("backend.main.check_llm_status") as mocked_llm,
        patch("backend.main.model_available", return_value=True),
    ):
        from backend.models.schemas import LLMStatus

        mocked_llm.return_value = LLMStatus(model="llama3.2:3b", reachable=True, model_pulled=True)
        response = client.get("/ready")

    assert response.status_code == 200
    body = response.json()
    assert body["ready"] is True
    assert body["checks"] == {"vector_store": True, "llm": True, "classifier": True}


@pytest.mark.parametrize(
    "vector_store_up,llm_up,classifier_up",
    [
        (False, True, True),
        (True, False, True),
        (True, True, False),
        (False, False, False),
    ],
)
def test_ready_returns_503_when_any_dependency_is_unavailable(vector_store_up, llm_up, classifier_up):
    with (
        patch("backend.main.vector_store_available", return_value=vector_store_up),
        patch("backend.main.check_llm_status") as mocked_llm,
        patch("backend.main.model_available", return_value=classifier_up),
    ):
        from backend.models.schemas import LLMStatus

        mocked_llm.return_value = LLMStatus(model="llama3.2:3b", reachable=llm_up, model_pulled=llm_up)
        response = client.get("/ready")

    assert response.status_code == 503
    body = response.json()
    assert body["ready"] is False


def test_ready_never_invokes_llm_generation():
    # check_llm_status() must only ever be asked for metadata (ollama.list()), never
    # generation -- assert the RAG-analysis LLM call path is never touched by /ready.
    with patch("backend.services.llm.ollama.chat") as mocked_chat:
        client.get("/ready")
    mocked_chat.assert_not_called()


def test_ready_is_public_no_auth_required():
    app.dependency_overrides.pop(require_auth, None)
    try:
        response = client.get("/ready")
        assert response.status_code in (200, 503)  # never 401
    finally:
        app.dependency_overrides[require_auth] = lambda: None
