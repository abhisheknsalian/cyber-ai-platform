import ollama

from backend.models.schemas import LLMStatus
from backend.rag.config import OLLAMA_MODEL


def check_llm_status() -> LLMStatus:
    """Lightweight Ollama status check -- lists installed models, does not run inference."""
    try:
        response = ollama.list()
        installed = {model.model for model in response.models}
        return LLMStatus(model=OLLAMA_MODEL, reachable=True, model_pulled=OLLAMA_MODEL in installed)
    except Exception:
        return LLMStatus(model=OLLAMA_MODEL, reachable=False, model_pulled=False)
