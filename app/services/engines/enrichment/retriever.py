"""Loads and looks up entries in the vulnerability knowledge base."""
import json
import logging
import re
import threading
from pathlib import Path

log = logging.getLogger("wsa.ai.retriever")

_KB_PATH = Path(__file__).resolve().parent.parent.parent.parent / "knowledge" / "vulnerability_knowledge.jsonl"

_lock = threading.Lock()
_cache = None  # list[dict], loaded once


def _normalize(text: str) -> str:
    return re.sub(r"[^a-z0-9 ]", "", (text or "").lower()).strip()


def _load():
    global _cache
    if _cache is not None:
        return _cache
    with _lock:
        if _cache is not None:
            return _cache
        entries = []
        if _KB_PATH.exists():
            with open(_KB_PATH, "r", encoding="utf-8") as fh:
                for i, line in enumerate(fh, start=1):
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        entries.append(json.loads(line))
                    except json.JSONDecodeError:
                        log.warning("Skipping malformed knowledge base line %d", i)
        else:
            log.warning("Knowledge base not found at %s", _KB_PATH)
        _cache = entries
        return _cache


def get_context(finding: dict) -> dict | None:
    """Find the best-matching knowledge base entry for a finding.

    Tries an exact CWE match first (once engines start setting `cwe`), then
    falls back to matching the finding name against each entry's
    `name_match` keyword list. Returns None if nothing matches -- the
    prompt builder handles that case by using a generic fallback context.
    """
    entries = _load()
    cwe = (finding.get("cwe") or "").strip().upper()
    if cwe:
        for entry in entries:
            if entry.get("cwe", "").upper() == cwe:
                return entry

    name = _normalize(finding.get("name", ""))
    if name:
        for entry in entries:
            for keyword in entry.get("name_match", []):
                if _normalize(keyword) in name:
                    return entry
    return None


def reload():
    """Clear the cache; next get_context() call re-reads the file from disk."""
    global _cache
    with _lock:
        _cache = None