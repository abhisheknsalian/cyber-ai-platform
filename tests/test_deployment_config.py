"""Phase 12: structural/sanity tests for the production deployment configuration.

These are not application-behavior tests -- they check that the files a production
deployment actually reads (docker-compose.prod.yml, .env.prod.example, the
Dockerfiles, the frontend's config-rendering pair) are internally consistent, contain
no real secrets, and match the specific things verified live during Phase 12 (see
README "Container Hardening" / "Networking"). uvicorn's own --proxy-headers/
--forwarded-allow-ips behavior cannot be exercised through FastAPI's TestClient (it
talks to the ASGI app directly, bypassing the uvicorn server layer entirely) -- that
mechanism was verified with a real uvicorn process instead (see the README) and is not
re-tested here.
"""

from pathlib import Path

import pytest
import yaml

REPO_ROOT = Path(__file__).resolve().parents[1]

# Same three placeholder strings backend/config_validation.py checks for -- a real
# secret must never look exactly like one of these.
_PLACEHOLDER_VALUES = {"changeme-generate-a-long-random-value", "changeme", "changeme-use-a-strong-password"}


@pytest.fixture(scope="module")
def prod_compose() -> dict:
    path = REPO_ROOT / "docker-compose.prod.yml"
    assert path.exists(), "docker-compose.prod.yml must exist"
    return yaml.safe_load(path.read_text(encoding="utf-8"))


def test_prod_compose_is_valid_yaml_with_expected_services(prod_compose):
    assert set(prod_compose["services"]) == {"backend", "frontend"}


def test_prod_compose_backend_and_frontend_are_read_only(prod_compose):
    for service in ("backend", "frontend"):
        assert prod_compose["services"][service]["read_only"] is True


def test_prod_compose_publishes_ports_to_loopback_only(prod_compose):
    for service in ("backend", "frontend"):
        for port_mapping in prod_compose["services"][service]["ports"]:
            assert port_mapping.startswith("127.0.0.1:"), (
                f"{service} port {port_mapping!r} is not bound to 127.0.0.1 -- "
                "production containers should not be directly reachable from outside the host"
            )


def test_prod_compose_backend_has_no_hardcoded_secret_values(prod_compose):
    backend_env = prod_compose["services"]["backend"]["environment"]
    for key in ("CYBER_AI_API_KEY", "CYBER_AI_USERNAME", "CYBER_AI_PASSWORD"):
        value = backend_env[key]
        assert value.startswith("${"), f"{key} must be a variable reference, not a literal value: {value!r}"


def test_prod_compose_persists_chroma_and_embedding_cache(prod_compose):
    volumes = prod_compose["services"]["backend"]["volumes"]
    mount_targets = [v.split(":")[1] if isinstance(v, str) else v["target"] for v in volumes]
    assert "/app/rag/chroma_db" in mount_targets
    assert "/app/.cache/huggingface" in mount_targets
    assert "hf_cache" in prod_compose["volumes"]


def test_prod_compose_forwarded_allow_ips_defaults_safely(prod_compose):
    """Defaults to uvicorn's own safe default (127.0.0.1) rather than something
    permissive -- see README "Security Deployment Audit" for why a broad default here
    would be a spoofing risk."""
    value = prod_compose["services"]["backend"]["environment"]["FORWARDED_ALLOW_IPS"]
    assert value == "${FORWARDED_ALLOW_IPS:-127.0.0.1}"


def test_env_prod_example_exists_and_contains_no_real_looking_secrets():
    path = REPO_ROOT / ".env.prod.example"
    assert path.exists()
    content = path.read_text(encoding="utf-8")

    for line in content.splitlines():
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        if key in {"CYBER_AI_API_KEY", "CYBER_AI_USERNAME", "CYBER_AI_PASSWORD"}:
            # Must be blank (the operator fills it in) or a documented placeholder --
            # never a real-looking secret committed to this template.
            assert value == "" or value in _PLACEHOLDER_VALUES, (
                f"{key} in .env.prod.example looks like a real secret value: {value!r}"
            )


def test_env_prod_example_is_gitignored_only_by_a_negated_pattern_not_the_real_file(monkeypatch):
    """Regression guard: a Phase 11 mistake in this project (.gitignore's `evaluation/`
    also matching backend/evaluation/) is the same class of bug that could hide this
    new template file from git if the negation pattern were missing or misordered."""
    gitignore = (REPO_ROOT / ".gitignore").read_text(encoding="utf-8")
    assert "!.env.prod.example" in gitignore


def test_dockerfile_declares_explicit_hf_cache_path():
    content = (REPO_ROOT / "Dockerfile").read_text(encoding="utf-8")
    assert "HF_HOME=/app/.cache/huggingface" in content
    mkdir_line = next(line for line in content.splitlines() if line.strip().startswith("RUN mkdir"))
    assert "/app/.cache/huggingface" in mkdir_line


def test_frontend_entrypoint_and_nginx_config_agree_on_the_config_js_path():
    """Regression guard for the read-only-filesystem bug found and fixed this phase:
    docker-entrypoint.sh used to write config.js into the static html root, which
    broke under --read-only (reproduced live: 'Read-only file system'). Both files
    must reference the same writable path outside that root."""
    entrypoint = (REPO_ROOT / "frontend" / "docker-entrypoint.sh").read_text(encoding="utf-8")
    nginx_conf = (REPO_ROOT / "frontend" / "nginx.conf").read_text(encoding="utf-8")

    assert "/run/frontend-config/config.js" in entrypoint
    assert "/run/frontend-config/config.js" in nginx_conf
    assert "/usr/share/nginx/html/config.js" not in entrypoint


def test_frontend_config_template_exposes_no_secret_shaped_keys():
    """The frontend must never receive anything secret -- structurally verified by
    checking the one file that defines its entire runtime config surface."""
    content = (REPO_ROOT / "frontend" / "config.template.js").read_text(encoding="utf-8")
    for forbidden in ("API_KEY", "PASSWORD", "SECRET", "TOKEN"):
        assert forbidden not in content.upper().replace("VITE_API_URL", "")


def test_reverse_proxy_example_contains_no_real_certificate_or_domain():
    path = REPO_ROOT / "deploy" / "nginx" / "reverse-proxy.conf.example"
    assert path.exists()
    content = path.read_text(encoding="utf-8")
    assert "<PLACEHOLDER-DOMAIN>" in content
    # No real-looking certificate bytes should ever appear in a tracked example file.
    assert "BEGIN CERTIFICATE" not in content
    assert "BEGIN PRIVATE KEY" not in content
