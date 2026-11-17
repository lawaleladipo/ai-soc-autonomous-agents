import json
import re
from typing import Any, Dict, Optional

from config.settings import Settings
from utils.logger import get_logger

logger = get_logger(__name__)
FENCE_RE = re.compile(r"^```(?:json)?\s*|\s*```$", re.IGNORECASE | re.MULTILINE)


def parse_llm_json(raw_text: str) -> Dict[str, Any]:
    """Safely parse JSON from LLM output even if wrapped in Markdown code fences."""
    cleaned = FENCE_RE.sub("", (raw_text or "").strip()).strip()
    return json.loads(cleaned)


def call_groq_json(
    system_prompt: str,
    user_prompt: str,
    max_tokens: int = 1200,
    temperature: float = 0.1,
) -> Optional[Dict[str, Any]]:
    """
    Execute a structured JSON call against Groq when GROQ_API_KEY is configured.
    Returns None cleanly when offline or unconfigured so deterministic agent fallbacks run.
    """
    settings = Settings()
    if not settings.GROQ_API_KEY:
        return None

    try:
        from groq import Groq

        client = Groq(api_key=settings.GROQ_API_KEY)
        resp = client.chat.completions.create(
            model=settings.GROQ_MODEL,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt},
            ],
            temperature=temperature,
            max_tokens=max_tokens,
            response_format={"type": "json_object"},
        )
        content = resp.choices[0].message.content or "{}"
        return parse_llm_json(content)
    except Exception as exc:
        logger.warning(f"LLM inference unavailable ({exc}); using deterministic fallback")
        return None
