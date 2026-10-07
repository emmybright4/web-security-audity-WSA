"""Orchestrates per-finding AI enrichment: retrieve -> prompt -> call -> validate."""
import logging

from ..ai_service import AIError, _chat
from .prompt_builder import build_prompt
from .retriever import get_context
from .validator import parse_and_validate

log = logging.getLogger("wsa.ai.enrich")

FAILED_RESULT = {"status": "failed", "explanation": None, "impact": None, "remediation": None}


def enrich_finding(config, finding: dict) -> dict:
    """Enrich a single finding dict. Never raises -- always returns a dict
    with a 'status' key ('done' or 'failed') plus the three text fields
    (None on failure).
    """
    kb_entry = get_context(finding)
    system, user = build_prompt(finding, kb_entry)

    try:
        raw = _chat(config, system, user, max_tokens=600)
    except AIError as exc:
        log.info("Enrichment skipped (AI not configured): %s", exc)
        return dict(FAILED_RESULT)
    except Exception as exc:
        log.warning("Enrichment request failed: %s", exc)
        return dict(FAILED_RESULT)

    parsed = parse_and_validate(raw)
    if parsed is None:
        log.warning("Enrichment response failed validation for finding %r", finding.get("name"))
        return dict(FAILED_RESULT)

    return {"status": "done", **parsed}