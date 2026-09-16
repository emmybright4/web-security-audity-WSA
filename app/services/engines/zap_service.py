"""OWASP ZAP API client service.

Uses ZAP's JSON API for spider + active scanning on authorized targets.
If ZAP is not reachable/configured, calls return a clean error and the scan
orchestrator falls back to the built-in scanner.
"""
import time

import requests

ZAP_TIMEOUT = 8


class ZAPError(Exception):
    pass


def _base_key(config):
    base = (config.get("ZAP_API_URL") or "").strip().rstrip("/")
    key = (config.get("ZAP_API_KEY") or "").strip()
    if not base:
        raise ZAPError("ZAP API URL is not configured. Set ZAP_API_URL in .env")
    return base, key


def _get(config, path, **params):
    """GET {base}/JSON/{path}/ with query params."""
    base, key = _base_key(config)
    params = {k: v for k, v in params.items() if v is not None}
    if key:
        params["apikey"] = key
    try:
        resp = requests.get(f"{base}/JSON/{path}/", params=params, timeout=ZAP_TIMEOUT)
    except requests.RequestException as exc:
        raise ZAPError(f"Cannot reach ZAP API: {exc.__class__.__name__}") from exc
    try:
        data = resp.json()
    except ValueError as exc:
        raise ZAPError(f"ZAP returned non-JSON response (HTTP {resp.status_code}).") from exc
    if isinstance(data, dict) and data.get("error"):
        raise ZAPError(f"ZAP error: {data['error']}")
    return data


def ping(config):
    """Return (ok, version, detail)."""
    try:
        data = _get(config, "core/view/version")
        return True, data.get("version", "unknown"), "OWASP ZAP API reachable."
    except ZAPError as exc:
        return False, "", str(exc)


def run_scan(config, target, options, progress_cb=None, finding_cb=None):
    """Run spider + active scan. Returns (findings, summary)."""
    findings, summary = [], {"engine": "zap", "alerts": 0}
    mode = options.get("zap_mode", "active")  # baseline|spider|active

    def prog(pct, label):
        if progress_cb:
            progress_cb(pct, f"[ZAP] {label}")

    ok, version, detail = ping(config)
    if not ok:
        raise ZAPError(detail)

    # -- spider -------------------------------------------------------------
    if mode in ("spider", "active"):
        prog(5, "Starting spider")
        data = _get(config, "spider/action/scan", url=target, recurse="true")
        scan_id = data.get("scan")
        _wait(config, "spider/view/status", scan_id, 5, 30, prog)

    # -- passive wait / active scan -------------------------------------------
    if mode == "baseline":
        prog(40, "Waiting for passive scanner")
        try:
            _get(config, "core/action/waitForPassiveScan")
        except ZAPError:
            pass  # best effort on older ZAP versions

    if mode == "active":
        prog(35, "Starting active scanner")
        data = _get(config, "ascan/action/scan", url=target, recurse="true")
        scan_id = data.get("scan")
        _wait(config, "ascan/view/status", scan_id, 35, 95, prog)

    # -- collect alerts ---------------------------------------------------------
    prog(97, "Collecting alerts")
    all_alerts, start = [], 0
    while True:
        page = _get(config, "core/view/alerts", baseurl=target, start=start, count=500)
        batch = page.get("alerts", [])
        all_alerts.extend(batch)
        if len(batch) < 500 or len(all_alerts) > 2000:
            break
        start += 500

    sev_map = {"high": "high", "medium": "medium", "low": "low",
               "informational": "informational", "info": "informational"}
    for a in all_alerts:
        sev = sev_map.get((a.get("risk") or "informational").lower(), "informational")
        confidence = (a.get("confidence") or "medium").lower()
        findings.append({
            "name": a.get("name") or "ZAP Alert",
            "severity": sev,
            "confidence": confidence,
            "description": a.get("description") or "",
            "evidence": a.get("evidence") or "",
            "remediation": a.get("solution") or "",
            "url": a.get("url") or target,
            "target_url": target,
            "detected_by": "OWASP ZAP",
        })
    summary["alerts"] = len(findings)
    prog(100, "ZAP scan complete")
    return findings, summary


def _wait(config, status_path, scan_id, start_pct, end_pct, prog):
    last = -1
    for _ in range(300):  # up to ~10 minutes
        try:
            data = _get(config, status_path, scanId=scan_id)
            pct = int(float(data.get("status", 0)))
        except Exception:
            time.sleep(2)
            continue
        if pct != last and prog:
            span = end_pct - start_pct
            prog(start_pct + int(span * pct / 100), f"engine progress {pct}%")
        last = pct
        if pct >= 100:
            return
        time.sleep(2)
