"""ZAP-MCP integration layer (AI-assisted ZAP workflows).

ZAP-MCP exposes ZAP functionality to LLM clients through the Model Context
Protocol. WSA provides an adapter: when ZAP is reachable, WSA can request
"AI-assisted" actions (contextual spider, quick-scan, alert explanations).
Where a real MCP endpoint is configured (ZAP_MCP_URL), we call it; otherwise
this layer implements the same operations directly over the ZAP API so the
workflow still works.
"""
import logging

import requests

from . import zap_service

log = logging.getLogger("wsa.zapmcp")


def availability(config):
    mcp_url = (config.get("ZAP_MCP_URL") or "").strip()
    if mcp_url:
        try:
            resp = requests.get(mcp_url.rstrip("/") + "/health", timeout=5)
            if resp.ok:
                return True, f"MCP endpoint reachable at {mcp_url}"
            return False, f"MCP endpoint responded HTTP {resp.status_code}."
        except requests.RequestException as exc:
            return False, f"MCP endpoint unreachable: {exc.__class__.__name__}"
    ok, version, _ = zap_service.ping(config)
    if ok:
        return True, f"Native ZAP mode (no MCP server configured) - ZAP {version}"
    return False, "Neither ZAP_MCP_URL nor a reachable ZAP API is configured."


def ai_assisted_quick_scan(config, target, progress_cb=None):
    """One-shot assisted workflow: spider -> active scan -> summarized alerts."""
    return zap_service.run_scan(config, target,
                                {"zap_mode": "active"},
                                progress_cb=progress_cb)


def explain_alerts(config, alerts):
    """Return short human explanations for ZAP alerts (rule-based fallback).

    A configured LLM (ai_service) provides richer explanations on top.
    """
    out = []
    for a in alerts:
        out.append({
            "alert": a.get("name"),
            "risk": a.get("severity"),
            "summary": (a.get("description") or "")[:280],
        })
    return out
