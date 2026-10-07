"""Validates that LLM output matches the required enrichment shape."""
import json
import re

_REQUIRED_KEYS = ("explanation", "impact", "remediation")
_FORBIDDEN_KEYS = ("severity", "confidence", "cwe", "risk_score")


def _strip_markdown_fences(text: str) -> str:
    text = text.strip()
    text = re.sub(r"^```(?:json)?\s*", "", text)
    text = re.sub(r"\s*```$", "", text)
    return text.strip()


def parse_and_validate(raw_text: str) -> dict | None:
    """Returns the parsed dict if valid, else None.

    Valid means: parses as JSON, has all three required string keys with
    non-empty content, and does not attempt to smuggle in a severity/
    confidence/cwe override (models sometimes do this unprompted).
    """
    if not raw_text or not raw_text.strip():
        return None

    cleaned = _strip_markdown_fences(raw_text)
    try:
        data = json.loads(cleaned)
    except json.JSONDecodeError:
        return None

    if not isinstance(data, dict):
        return None

    for key in _REQUIRED_KEYS:
        value = data.get(key)
        if not isinstance(value, str) or not value.strip():
            return None

    result = {k: data[k].strip() for k in _REQUIRED_KEYS}

    if any(k in data for k in _FORBIDDEN_KEYS):
        import logging
        logging.getLogger("wsa.ai.validator").warning(
            "AI output included forbidden override keys: %s",
            [k for k in _FORBIDDEN_KEYS if k in data])

    return result