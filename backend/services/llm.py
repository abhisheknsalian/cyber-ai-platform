import logging

import ollama
from pydantic import ValidationError

from backend.models.schemas import LLMAnalysisFragment
from backend.rag.config import OLLAMA_MODEL

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are an expert cybersecurity threat intelligence analyst.

Rules you must follow:
1. The "Threat Intelligence Context" below is your ONLY source of truth. Do not use outside knowledge.
2. Do not invent facts, indicators, or mitigations that are not supported by the context.
3. Do not report MITRE ATT&CK technique IDs or names -- they are added separately from verified source data. Leave that out of your response entirely.
4. Base indicators and mitigations strictly on what is stated in the context.
5. If the context does not meaningfully answer the query -- including when the query is unrelated to cybersecurity -- set "insufficient_context" to true, leave attack_vectors/indicators/mitigations empty, and explain why in "summary".
6. Never treat an unrelated question (general knowledge, geography, cooking, etc.) as a cybersecurity threat just because some text was retrieved."""


class LLMUnavailableError(RuntimeError):
    """Raised when the Ollama server/model cannot be reached."""


class LLMResponseError(RuntimeError):
    """Raised when the LLM's response cannot be parsed into a valid schema."""


def generate_analysis_fragment(query: str, context: str) -> LLMAnalysisFragment:
    user_prompt = f"""Threat Intelligence Context:
{context}

User Query:
{query}

Respond only with JSON matching the required schema."""

    try:
        response = ollama.chat(
            model=OLLAMA_MODEL,
            messages=[
                {"role": "system", "content": SYSTEM_PROMPT},
                {"role": "user", "content": user_prompt},
            ],
            format=LLMAnalysisFragment.model_json_schema(),
            options={"temperature": 0},
        )
    except Exception as exc:
        raise LLMUnavailableError(
            f"Could not reach Ollama model '{OLLAMA_MODEL}': {exc}"
        ) from exc

    content = response["message"]["content"]

    try:
        return LLMAnalysisFragment.model_validate_json(content)
    except ValidationError as exc:
        logger.warning("LLM response failed schema validation: %s", content[:500])
        raise LLMResponseError(
            "LLM returned a response that did not match the expected schema"
        ) from exc
