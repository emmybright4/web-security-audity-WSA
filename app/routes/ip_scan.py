"""IP Scan API: create, list, detail, cancel, delete IP scans.

Provides REST endpoints for the IP/Network scanning feature.
"""
import logging
import re
import threading
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone

from flask import Blueprint, jsonify, request
from flask_login import current_user
from sqlalchemy import desc

from ..extensions import db, socketio
from ..models import IPScan, IPScanHost, IPScanPort, IPScanVulnerability
from ..services import notification_service
from ..services.engines import ip_scanner
from ._api_guard import api_login_required

log = logging.getLogger("wsa.ip_scan")

bp = Blueprint("ip_scan", __name__, url_prefix="/api/ip-scan")

VALID_PROFILES = {"quick", "standard", "full", "custom"}


def _notify(fn, *args):
    """Fire a notification; delivery problems never affect scan state."""
    try:
        fn(*args)
    except Exception as exc:
        log.warning("notification %s failed: %s", getattr(fn, "__name__", fn), exc)

# Scan cancellation registry
_cancelled = set()
_lock = threading.Lock()
_scan_threads = {}

# Sequential scan number counter (per-session, resets on server restart)
_scan_counter = 0
_counter_lock = threading.Lock()


def _next_scan_number():
    global _scan_counter
    with _counter_lock:
        # Find highest existing scan_number in DB
        if _scan_counter == 0:
            highest = db.session.query(db.func.max(IPScan.scan_number)).scalar() or 0
            _scan_counter = highest
        _scan_counter += 1
        return _scan_counter


def _emit(event, payload):
    try:
        socketio.emit(event, payload)
    except Exception:
        pass


def _is_cancelled(scan_id):
    with _lock:
        return scan_id in _cancelled


def _request_cancel(scan_id):
    """Flag a *running* IP scan for cancellation.

    Guarded by the worker registry for the same reason as the web scanner: a
    flag set for a scan that has no worker is never cleared, SQLite reuses the
    id of a deleted row, and the next scan would start already cancelled.
    """
    with _lock:
        if scan_id in _scan_threads:
            _cancelled.add(scan_id)


def _set_scan(scan, **fields):
    for k, v in fields.items():
        setattr(scan, k, v)
    db.session.commit()


def _run_ip_scan(scan_id):
    """Background worker for an IP scan."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        # deleted before the worker ran: drop the bookkeeping so a reused id
        # does not inherit a stale cancellation flag
        with _lock:
            _scan_threads.pop(scan_id, None)
            _cancelled.discard(scan_id)
        return

    options = scan.options or {}
    target = scan.target
    started = time.time()

    _set_scan(scan, status="running", progress=2,
              started_at=datetime.now(timezone.utc),
              current_step="Initializing IP scanner", error_message="")
    _emit("ip_scan_started", {"scan_id": scan_id, "target": target, "status": "running"})

    def progress_cb(pct, label):
        if _is_cancelled(scan_id):
            raise _Cancelled()
        try:
            fresh = db.session.get(IPScan, scan_id)
            if fresh:
                _set_scan(fresh, progress=max(fresh.progress or 0, int(pct)),
                          current_step=label)
            _emit("ip_scan_progress", {"scan_id": scan_id, "progress": int(pct), "step": label})
        except _Cancelled:
            raise
        except Exception:
            pass

    try:
        # Run the scanner
        results, summary = ip_scanner.scan_network(target, options, progress_cb=progress_cb)

        if _is_cancelled(scan_id):
            raise _Cancelled()

        # Store results in DB
        total_vulns = 0
        critical = high = medium = low = info = 0

        for host_data in results:
            ip = host_data.get("ip_address", "")
            hostname = host_data.get("hostname", "")
            os_det = host_data.get("os_detection", "")
            mac = host_data.get("mac_address", "")
            status = host_data.get("status", "down")
            risk = host_data.get("risk_level", "none")
            open_count = len(host_data.get("open_ports", []))
            svc_count = len(host_data.get("services", []))

            host = IPScanHost(
                scan_id=scan_id, ip_address=ip, hostname=hostname,
                os_detection=os_det, mac_address=mac, status=status,
                open_ports_count=open_count, services_count=svc_count,
                risk_level=risk,
            )
            db.session.add(host)
            db.session.flush()

            # Store ports
            for port_info in host_data.get("services", []):
                port = IPScanPort(
                    scan_id=scan_id, host_id=host.id,
                    port_number=port_info["port"],
                    protocol="tcp",
                    service=port_info.get("service", ""),
                    version=port_info.get("version", ""),
                    banner=port_info.get("banner", ""),
                    state="open",
                )
                db.session.add(port)

            # Store vulnerabilities
            vuln_count = 0
            for f in host_data.get("findings", []):
                sev = f.get("severity", "informational")
                vuln = IPScanVulnerability(
                    scan_id=scan_id, host_id=host.id,
                    name=f.get("name", "Unnamed Finding"),
                    vuln_type=f.get("vuln_type", ""),
                    severity=sev,
                    confidence=f.get("confidence", "medium"),
                    host_ip=f.get("host_ip", ip),
                    port=f.get("port"),
                    service=f.get("service", ""),
                    cve_id=f.get("cve_id", ""),
                    cvss_score=f.get("cvss_score"),
                    affected_software=f.get("affected_software", ""),
                    description=f.get("description", ""),
                    evidence=f.get("evidence", ""),
                    recommendation=f.get("recommendation", ""),
                    detected_by="WSA IP Scanner",
                )
                db.session.add(vuln)
                vuln_count += 1
                total_vulns += 1

                if sev == "critical": critical += 1
                elif sev == "high": high += 1
                elif sev == "medium": medium += 1
                elif sev == "low": low += 1
                else: info += 1

                _emit("new_finding", {
                    "scan_id": scan_id, "name": f.get("name"),
                    "severity": sev, "host_ip": ip,
                })

            host.vulnerabilities_count = vuln_count
            db.session.commit()

        # Update scan summary
        fresh = db.session.get(IPScan, scan_id)
        _set_scan(fresh, status="completed", progress=100,
                  current_step="Scan completed",
                  completed_at=datetime.now(timezone.utc),
                  hosts_discovered=len(results),
                  open_ports_count=summary.get("open_ports", 0),
                  services_detected=summary.get("services", 0),
                  vulnerabilities_count=total_vulns,
                  critical_count=critical, high_count=high,
                  medium_count=medium, low_count=low,
                  informational_count=info)

        _notify(notification_service.notify_ip_scan_completed, fresh)
        _emit("ip_scan_completed", {
            "scan_id": scan_id, "status": "completed",
            "target": target, "scan_number": fresh.scan_number,
            "hosts": len(results), "vulnerabilities": total_vulns,
        })
        log.info("IP scan %s completed: %d hosts, %d vulns in %.1fs",
                 scan_id, len(results), total_vulns, time.time() - started)

    except _Cancelled:
        fresh = db.session.get(IPScan, scan_id)
        if fresh:
            _set_scan(fresh, status="cancelled", current_step="Scan cancelled",
                      completed_at=datetime.now(timezone.utc))
        _emit("ip_scan_completed", {"scan_id": scan_id, "status": "cancelled"})
    except Exception as exc:
        log.exception("IP scan %s failed", scan_id)
        fresh = db.session.get(IPScan, scan_id)
        if fresh:
            _set_scan(fresh, status="failed", current_step="Scan failed",
                      error_message=str(exc)[:1000],
                      completed_at=datetime.now(timezone.utc))
            _notify(notification_service.notify_ip_scan_failed, fresh)
        _emit("ip_scan_completed", {"scan_id": scan_id, "status": "failed", "error": str(exc)[:300]})
    finally:
        with _lock:
            _scan_threads.pop(scan_id, None)
            _cancelled.discard(scan_id)


class _Cancelled(Exception):
    pass


# ------------------------------------------------------------------ API Routes ----


@bp.get("")
@api_login_required
def list_ip_scans():
    """List all IP scans, newest first."""
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        scans = IPScan.query.order_by(desc(IPScan.created_at)).limit(limit).all()
        return jsonify(scans=[s.to_dict() for s in scans])
    except Exception as exc:
        return jsonify(error=f"Failed to list IP scans: {exc}"), 500


@bp.post("")
@api_login_required
def create_ip_scan():
    """Start a new IP scan."""
    data = request.get_json(silent=True) or {}
    target = (data.get("target") or "").strip()
    if not target:
        return jsonify(error="Target is required. Enter an IP address, range, or CIDR."), 400

    # Validate target format
    ip_re = re.compile(
        r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})"
        r"([\/\-]\d{1,3}(?:\.\d{1,3}\.\d{1,3}\.\d{1,3})?)?$"
    )
    if not ip_re.match(target) and "/" not in target and "-" not in target:
        # Try hostname resolution
        import socket as _sock
        try:
            _sock.gethostbyname(target)
        except _sock.gaierror:
            return jsonify(error="Invalid target. Enter a valid IP address, range (e.g. 192.168.1.1-50), or CIDR (e.g. 192.168.1.0/24)."), 400

    scan_profile = (data.get("scan_profile") or "quick").lower()
    if scan_profile not in VALID_PROFILES:
        return jsonify(error=f"Invalid scan profile '{scan_profile}'."), 400

    authorized = str(data.get("authorized", "")).lower()
    if authorized not in ("true", "1", "yes", "on"):
        return jsonify(error="You must confirm you are authorized to scan this target."), 400

    # Parse options
    def as_bool(key, default=False):
        v = data.get(key, default)
        if isinstance(v, bool):
            return v
        return str(v).lower() in ("true", "1", "yes", "on")

    options = {
        "scan_profile": scan_profile,
        "host_discovery": as_bool("host_discovery", True),
        "port_discovery": as_bool("port_discovery", True),
        "service_detection": as_bool("service_detection", True),
        "version_detection": as_bool("version_detection", True),
        "os_detection": as_bool("os_detection", True),
        "vulnerability_detection": as_bool("vulnerability_detection", True),
        "ssl_tls_checks": as_bool("ssl_tls_checks", True),
    }

    scan_number = _next_scan_number()

    try:
        scan = IPScan(
            target=target, scan_profile=scan_profile, status="pending",
            progress=0, options=options, current_step="Queued",
            scan_number=scan_number,
            user_id=getattr(current_user, "row", None) and current_user.row.id,
        )
        db.session.add(scan)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log.exception("IP scan create failed")
        return jsonify(error=f"Could not create IP scan: {exc}"), 500

    # Launch background thread
    def runner():
        with socketio.server.app.app_context():
            _run_ip_scan(scan.id)

    # Need app context for the thread
    from flask import current_app
    app = current_app._get_current_object()

    def _runner():
        with app.app_context():
            _run_ip_scan(scan.id)

    thread = threading.Thread(target=_runner, name=f"ip-scan-{scan.id}", daemon=True)
    with _lock:
        _scan_threads[scan.id] = thread
    thread.start()

    return jsonify(message="IP scan started.", scan=scan.to_dict()), 201


@bp.get("/<int:scan_id>")
@api_login_required
def get_ip_scan(scan_id):
    """Get detailed IP scan results."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404

    hosts = IPScanHost.query.filter_by(scan_id=scan_id).all()
    host_list = []
    for h in hosts:
        ports = IPScanPort.query.filter_by(host_id=h.id).all()
        vulns = IPScanVulnerability.query.filter_by(host_id=h.id).all()
        hd = h.to_dict()
        hd["ports"] = [p.to_dict() for p in ports]
        hd["vulns"] = [v.to_dict() for v in vulns]
        host_list.append(hd)

    return jsonify(scan=scan.to_dict(), hosts=host_list)


@bp.get("/<int:scan_id>/hosts")
@api_login_required
def get_ip_scan_hosts(scan_id):
    """Get all hosts for an IP scan."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404
    hosts = IPScanHost.query.filter_by(scan_id=scan_id).all()
    return jsonify(hosts=[h.to_dict() for h in hosts])


@bp.get("/<int:scan_id>/ports")
@api_login_required
def get_ip_scan_ports(scan_id):
    """Get all open ports for an IP scan."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404
    ports = IPScanPort.query.filter_by(scan_id=scan_id).all()
    return jsonify(ports=[p.to_dict() for p in ports])


@bp.get("/<int:scan_id>/vulnerabilities")
@api_login_required
def get_ip_scan_vulns(scan_id):
    """Get all vulnerabilities for an IP scan."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404

    # Filter by type if requested
    vuln_type = (request.args.get("type") or "").strip()
    severity = (request.args.get("severity") or "").strip().lower()

    q = IPScanVulnerability.query.filter_by(scan_id=scan_id)
    if vuln_type:
        q = q.filter(IPScanVulnerability.vuln_type == vuln_type)
    if severity:
        if severity == "high":
            q = q.filter(IPScanVulnerability.severity.in_(("high", "critical")))
        else:
            q = q.filter(IPScanVulnerability.severity == severity)

    vulns = q.all()
    return jsonify(vulnerabilities=[v.to_dict() for v in vulns], count=len(vulns))


@bp.get("/<int:scan_id>/vulnerability-trend")
@api_login_required
def ip_vuln_trend(scan_id):
    """Get vulnerability distribution data for charts."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404

    vulns = IPScanVulnerability.query.filter_by(scan_id=scan_id).all()

    # Group by host
    by_host = {}
    for v in vulns:
        ip = v.host_ip or "Unknown"
        if ip not in by_host:
            by_host[ip] = {"critical": 0, "high": 0, "medium": 0, "low": 0, "informational": 0}
        sev = v.severity if v.severity in by_host[ip] else "informational"
        by_host[ip][sev] += 1

    # Group by type
    by_type = {}
    for v in vulns:
        t = v.vuln_type or "other"
        if t not in by_type:
            by_type[t] = 0
        by_type[t] += 1

    return jsonify(
        by_host=by_host,
        by_type=by_type,
        total=len(vulns),
    )


@bp.get("/history")
@api_login_required
def ip_scan_history():
    """Get scan history with sequential numbering."""
    try:
        scans = (IPScan.query
                 .filter(IPScan.status.in_(["completed", "failed", "cancelled"]))
                 .order_by(desc(IPScan.created_at)).limit(100).all())
        return jsonify(scans=[s.to_dict() for s in scans])
    except Exception as exc:
        return jsonify(error=f"Failed to load scan history: {exc}"), 500


@bp.get("/summary")
@api_login_required
def ip_scan_summary():
    """Get latest scan summary for the dashboard cards."""
    latest = IPScan.query.filter_by(status="completed").order_by(desc(IPScan.created_at)).first()
    if latest is None:
        return jsonify(
            hosts_discovered=0, open_ports=0, services_detected=0,
            vulnerabilities=0, critical=0, high=0, medium=0, low=0,
            informational=0, empty=True, scan_number=0,
        )
    return jsonify(
        hosts_discovered=latest.hosts_discovered,
        open_ports=latest.open_ports_count,
        services_detected=latest.services_detected,
        vulnerabilities=latest.vulnerabilities_count,
        critical=latest.critical_count,
        high=latest.high_count,
        medium=latest.medium_count,
        low=latest.low_count,
        informational=latest.informational_count,
        empty=False,
        scan_number=latest.scan_number,
        scan_id=latest.id,
    )


@bp.post("/<int:scan_id>/cancel")
@api_login_required
def cancel_ip_scan(scan_id):
    """Cancel a running IP scan."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404
    if scan.status not in ("pending", "running"):
        return jsonify(error=f"Scan is already {scan.status}; cannot cancel."), 400
    _request_cancel(scan_id)
    return jsonify(message="Cancellation requested.", scan=scan.to_dict())


@bp.delete("/<int:scan_id>")
@api_login_required
def delete_ip_scan(scan_id):
    """Delete an IP scan and its results."""
    scan = db.session.get(IPScan, scan_id)
    if scan is None:
        return jsonify(error="IP scan not found."), 404
    _request_cancel(scan_id)
    try:
        db.session.delete(scan)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not delete scan: {exc}"), 500
    return jsonify(message=f"IP scan #{scan_id} deleted.")
