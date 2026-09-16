"""Real tool availability checks for the Tools & Integrations page."""
import logging
import shutil
import subprocess

import requests

log = logging.getLogger("wsa.tools")

CHECKERS = {}


def checker(name):
    def deco(fn):
        CHECKERS[name] = fn
        return fn
    return deco


@checker("OWASP ZAP")
def check_zap(config):
    from .engines import zap_service
    ok, version, detail = zap_service.ping(config)
    return ("connected" if ok else "not_configured"), version, detail


@checker("ZAP-MCP")
def check_zap_mcp(config):
    from .engines import zap_mcp
    ok, detail = zap_mcp.availability(config)
    return ("connected" if ok else "not_configured"), "", detail


@checker("Playwright")
def check_playwright(config):
    from .engines import playwright_service
    ok, detail = playwright_service.availability()
    return ("connected" if ok else "not_configured"), detail if ok else "", "" if ok else detail


@checker("Nuclei")
def check_nuclei(config):
    from .engines import nuclei_service
    ok, detail = nuclei_service.availability(config)
    return ("connected" if ok else "not_configured"), detail if ok else "", "" if ok else detail


@checker("gosqli")
def check_gosqli(config):
    from .engines import sqli_service
    ok, detail = sqli_service.availability(config)
    if ok:
        return "connected", detail, "External gosqli binary available; built-in timing module also active."
    return "not_configured", "", detail


@checker("AI / LLM")
def check_ai(config):
    from .engines import ai_service
    ok, detail = ai_service.availability(config)
    return ("connected" if ok else "not_configured"), detail if ok else "", "" if ok else detail


def check_all(app):
    """Run every checker; persist results in ToolIntegration. Returns dict keyed by name."""
    from ..models import ToolIntegration, db
    config = app.config
    results = {}
    for name, fn in CHECKERS.items():
        try:
            status, version, detail = fn(config)
        except Exception as exc:
            log.warning("Tool check failed for %s: %s", name, exc)
            status, version, detail = "error", "", str(exc)
        results[name] = {"status": status, "version": version, "detail": detail}
        row = ToolIntegration.query.filter_by(name=name).first()
        if row:
            from ..models import utcnow
            row.status = status
            row.version = version
            row.detail = detail
            row.last_checked = utcnow()
    db.session.commit()
    return results
