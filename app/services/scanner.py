"""Scan orchestrator: runs engine pipeline in a background thread.

Engine order (as enabled by scan options):
  1. Playwright crawl (optional, JS-rendered URL discovery)
  2. OWASP ZAP spider/active scan (optional)
  3. Nuclei templates (optional)
  4. Time-based SQLi module (optional)
  5. WSA Built-in scanner (always; the zero-dependency engine)

Emits Socket.IO events for every state change; UI has a polling fallback.
"""
import logging
import threading
import time
from datetime import datetime, timezone

from ..extensions import db, socketio
from ..models import Vulnerability
from . import notification_service
from .engines import (builtin_scanner, nuclei_service, playwright_service, sqli_service,
                      zap_service)

log = logging.getLogger("wsa.orchestrator")

_scan_threads = {}
_cancellations = set()
_lock = threading.Lock()


def is_cancelled(scan_id):
    return scan_id in _cancellations


def request_cancel(scan_id):
    """Flag a *running* scan for cancellation.

    Only a scan with a live worker thread is flagged. The flag is cleared by
    that thread when it exits, so flagging an idle or already-finished scan
    would leave a stale entry behind -- and SQLite reuses the primary key of a
    deleted row, so the *next* scan could inherit the flag and be cancelled the
    moment it starts.
    """
    with _lock:
        if scan_id in _scan_threads:
            _cancellations.add(scan_id)


def _emit(event, payload, room=None):
    """Broadcast a scan event to its owner's room (or everyone when no owner)."""
    try:
        if room:
            socketio.emit(event, payload, room=room)
        else:
            socketio.emit(event, payload)
    except Exception as exc:  # socket down is never fatal
        log.debug("emit %s failed: %s", event, exc)


def _notify(fn, *args):
    """Fire a notification; delivery problems never affect scan state."""
    try:
        fn(*args)
    except Exception as exc:
        log.warning("notification %s failed: %s", getattr(fn, "__name__", fn), exc)


def start_scan(app, scan_id):
    """Launch the scan in a daemon thread."""
    with app.app_context():
        scan = None
        from ..models import Scan
        scan = db.session.get(Scan, scan_id)

    def runner():
        with app.app_context():
            _run_scan(app, scan_id)

    thread = threading.Thread(target=runner, name=f"wsa-scan-{scan_id}", daemon=True)
    with _lock:
        _scan_threads[scan_id] = thread
    thread.start()


def _set_scan(scan, **fields):
    for k, v in fields.items():
        setattr(scan, k, v)
    db.session.commit()


def _run_scan(app, scan_id):
    from ..models import Scan
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        # The row was deleted before this worker got to it. Release the
        # bookkeeping now: nobody else clears it, and a leftover cancellation
        # flag would cancel the next scan that reuses this id.
        with _lock:
            _scan_threads.pop(scan_id, None)
            _cancellations.discard(scan_id)
        return

    options = scan.options or {}
    target = scan.target_url
    config = app.config
    started = time.time()
    # Live events are delivered only to the account that owns the scan. Without
    # this a scan in one workspace pushed findings into everyone else's browser.
    owner_room = f"user:{scan.user_id}" if scan.user_id else None

    _set_scan(scan, status="running", progress=2, started_at=datetime.now(timezone.utc),
              current_step="Initializing scan engines", error_message="")
    _emit("scan_started", {"scan_id": scan_id, "target_url": target,
                           "scan_type": scan.scan_type, "status": "running", "progress": 2},
          room=owner_room)

    def progress_cb(pct, label):
        if is_cancelled(scan_id):
            raise _Cancelled()
        try:
            fresh = db.session.get(Scan, scan_id)
            _set_scan(fresh, progress=max(fresh.progress, int(pct)), current_step=label)
            _emit("scan_progress", {"scan_id": scan_id, "progress": int(pct), "step": label,
                                    "status": "running"}, room=owner_room)
        except _Cancelled:
            raise
        except Exception as exc:
            log.debug("progress update failed: %s", exc)

    inserted = 0
    try:
        engines = []
        if options.get("playwright_enabled"):
            engines.append(("playwright", _run_playwright, 0))
        if options.get("zap_enabled") and (config.get("ZAP_API_URL") or "").strip():
            engines.append(("zap", _run_zap, 15))
        if options.get("nuclei_enabled"):
            engines.append(("nuclei", _run_nuclei, 15))
        if options.get("sqli_enabled"):
            engines.append(("sqli", _run_sqli, 10))
        engines.append(("builtin", _run_builtin, 40))

        total = len(engines)
        for i, (name, fn, weight) in enumerate(engines):
            if is_cancelled(scan_id):
                raise _Cancelled()
            base = int(100 * i / total)
            span = max(5, int(100 / total) - (weight if name != "builtin" else 0))

            def engine_progress(pct, label, _base=base, _span=span):
                progress_cb(_base + int(_span * pct / 100), label)

            findings, engine_error = fn(config, target, options, engine_progress, scan_id)
            if engine_error:
                current = db.session.get(Scan, scan_id)
                note = f"[{name}] {engine_error}"
                current.error_message = ((current.error_message + " | " + note)
                                         if current.error_message else note)
                db.session.commit()
            for f in findings:
                if is_cancelled(scan_id):
                    raise _Cancelled()
                v = Vulnerability(
                    scan_id=scan_id,
                    name=f.get("name", "Unnamed Finding"),
                    severity=f.get("severity", "informational"),
                    confidence=f.get("confidence", "medium"),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    remediation=f.get("remediation", ""),
                    target_url=f.get("target_url") or target,
                    url=f.get("url", ""),
                    detected_by=f.get("detected_by", "WSA Built-in Scanner"),
                )
                db.session.add(v)
                db.session.commit()
                inserted += 1
                _emit("new_finding", {
                    "scan_id": scan_id, "id": v.id, "name": v.name, "severity": v.severity,
                    "detected_by": v.detected_by, "url": v.url or v.target_url,
                }, room=owner_room)
                if str(v.severity or "").lower() in ("critical", "high"):
                    # Alert only for a finding that is really stored, using its
                    # own severity, CVE/CVSS fields and scan.
                    _notify(notification_service.notify_critical_vulnerability, v)

        if is_cancelled(scan_id):
            raise _Cancelled()

        fresh = db.session.get(Scan, scan_id)
        _set_scan(fresh, status="completed", progress=100,
                  current_step="Scan completed",
                  completed_at=datetime.now(timezone.utc))
        counts = fresh.severity_counts()
        _notify(notification_service.notify_scan_completed, fresh)
        _emit("scan_completed", {
            "scan_id": scan_id, "status": "completed", "progress": 100,
            "target_url": target, "findings_count": inserted, **counts,
        }, room=owner_room)
        log.info("Scan %s completed: %d findings in %.1fs", scan_id, inserted, time.time() - started)

    except _Cancelled:
        fresh = db.session.get(Scan, scan_id)
        _set_scan(fresh, status="cancelled", current_step="Scan cancelled by user",
                  completed_at=datetime.now(timezone.utc))
        _emit("scan_completed", {"scan_id": scan_id, "status": "cancelled",
                                 "target_url": target, "findings_count": inserted},
              room=owner_room)
    except Exception as exc:
        log.exception("Scan %s failed", scan_id)
        fresh = db.session.get(Scan, scan_id)
        _set_scan(fresh, status="failed", current_step="Scan failed",
                  error_message=str(exc)[:1000],
                  completed_at=datetime.now(timezone.utc))
        # The status is already committed above; the alert only reports it.
        _notify(notification_service.notify_scan_failed, fresh)
        _emit("scan_completed", {"scan_id": scan_id, "status": "failed",
                                 "target_url": target, "error": str(exc)[:300],
                                 "findings_count": inserted}, room=owner_room)
    finally:
        with _lock:
            _scan_threads.pop(scan_id, None)
            _cancellations.discard(scan_id)


class _Cancelled(Exception):
    pass


# ---- individual engine runners -----------------------------------------------

def _run_builtin(config, target, options, progress_cb, scan_id):
    findings, summary = builtin_scanner.scan(target, options, progress_cb=progress_cb)
    return findings, ""


def _run_zap(config, target, options, progress_cb, scan_id):
    try:
        findings, summary = zap_service.run_scan(config, target, options, progress_cb=progress_cb)
        return findings, ""
    except zap_service.ZAPError as exc:
        return [], str(exc)


def _run_playwright(config, target, options, progress_cb, scan_id):
    urls, pages_meta, findings, error = playwright_service.crawl(target, options, progress_cb)
    return findings, error


def _run_nuclei(config, target, options, progress_cb, scan_id):
    findings, summary, error = nuclei_service.scan(config, target, options, progress_cb)
    return findings, error


def _run_sqli(config, target, options, progress_cb, scan_id):
    findings, summary, error = sqli_service.scan(config, target, options, progress_cb)
    return findings, error
