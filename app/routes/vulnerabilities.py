"""Vulnerability findings API: list/filter/search/sort, update status, notes, delete.

Lists BOTH web findings (``Vulnerability``) and network findings
(``IPScanVulnerability``) so the Findings page shows every finding the platform
discovered. Each item carries a ``source`` of ``"web"`` or ``"network"``.
"""
from flask import Blueprint, jsonify, request
from sqlalchemy import desc, or_

from ..extensions import db
from ..models import IPScan, IPScanVulnerability, Vulnerability
from ._api_guard import api_login_required

bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")

SEVERITIES = ("high", "medium", "low", "informational", "critical", "info")
STATUSES = ("open", "in_review", "resolved", "false_positive")

SOURCE_WEB = "web"
SOURCE_NETWORK = "network"


def _severity_filter(q, column, severity):
    """Apply the shared severity shorthand (high|info expand to aliases)."""
    if severity == "high":
        return q.filter(column.in_(("high", "critical")))
    if severity == "info":
        return q.filter(column.in_(("informational", "info")))
    return q.filter(column == severity)


def _network_to_dict(v):
    """Normalize an IP-scan finding into the same shape as web findings."""
    d = v.to_dict()
    d["source"] = SOURCE_NETWORK
    d["remediation"] = v.recommendation or ""
    d["notes"] = ""
    d["url"] = f"{v.host_ip}:{v.port}" if v.port else (v.host_ip or "")
    d["target_url"] = (v.scan.target if v.scan else "") or v.host_ip or ""
    return d


@bp.get("")
@api_login_required
def list_vulns():
    try:
        search = (request.args.get("search") or "").strip()
        severity = (request.args.get("severity") or "").strip().lower()
        target = (request.args.get("target") or "").strip()
        scan_id = request.args.get("scan_id", type=int)
        status = (request.args.get("status") or "").strip()
        sort = request.args.get("sort", "newest")
        limit = min(int(request.args.get("limit", 200)), 1000)

        # ---- web findings -------------------------------------------------
        web_q = Vulnerability.query
        if search:
            like = f"%{search}%"
            web_q = web_q.filter(or_(Vulnerability.name.ilike(like),
                                    Vulnerability.description.ilike(like),
                                    Vulnerability.url.ilike(like),
                                    Vulnerability.target_url.ilike(like)))
        if severity:
            web_q = _severity_filter(web_q, Vulnerability.severity, severity)
        if target:
            web_q = web_q.filter(Vulnerability.target_url.ilike(f"%{target}%"))
        if scan_id:
            web_q = web_q.filter(Vulnerability.scan_id == scan_id)
        if status:
            web_q = web_q.filter(Vulnerability.status == status)

        # ---- network findings ---------------------------------------------
        net_q = IPScanVulnerability.query
        if search:
            like = f"%{search}%"
            net_q = net_q.filter(or_(IPScanVulnerability.name.ilike(like),
                                     IPScanVulnerability.description.ilike(like),
                                     IPScanVulnerability.host_ip.ilike(like),
                                     IPScanVulnerability.affected_software.ilike(like),
                                     IPScanVulnerability.cve_id.ilike(like)))
        if severity:
            net_q = _severity_filter(net_q, IPScanVulnerability.severity, severity)
        if target:
            like = f"%{target}%"
            net_q = (net_q.join(IPScan, IPScanVulnerability.scan_id == IPScan.id)
                          .filter(or_(IPScanVulnerability.host_ip.ilike(like),
                                      IPScan.target.ilike(like))))
        if scan_id:
            net_q = net_q.filter(IPScanVulnerability.scan_id == scan_id)
        if status:
            net_q = net_q.filter(IPScanVulnerability.status == status)

        # How many findings match in total, before the display limit is applied.
        total = web_q.count() + net_q.count()

        # Each source is ordered newest-first *before* the limit is applied. Without
        # the explicit order the database returns rows oldest-first, so a limit would
        # silently keep the oldest findings and drop everything the latest scans found.
        items = []
        for v in web_q.order_by(desc(Vulnerability.created_at)).limit(limit).all():
            items.append({**v.to_dict(), "source": SOURCE_WEB})
        items.extend(_network_to_dict(v) for v in
                     net_q.order_by(desc(IPScanVulnerability.created_at)).limit(limit).all())

        # Merge into a single ordered list (DB-level ordering can't span the
        # two tables, so sort the combined set in Python).
        if sort == "name":
            items.sort(key=lambda i: (i.get("name") or "").lower())
        elif sort == "oldest":
            items.sort(key=lambda i: i.get("created_at") or "")
        else:
            items.sort(key=lambda i: i.get("created_at") or "", reverse=True)

        items = items[:limit]
        return jsonify(vulnerabilities=items, count=len(items), total=total)
    except Exception as exc:
        return jsonify(error=f"Failed to load findings: {exc}"), 500


@bp.get("/targets")
@api_login_required
def distinct_targets():
    try:
        web_targets = {r[0] for r in db.session.query(Vulnerability.target_url).distinct().all() if r[0]}
        net_targets = {r[0] for r in db.session.query(IPScan.target).distinct().all() if r[0]}
        return jsonify(targets=sorted(web_targets | net_targets))
    except Exception as exc:
        return jsonify(error=str(exc)), 500


def _is_network():
    return (request.args.get("source") or SOURCE_WEB).strip().lower() == SOURCE_NETWORK


@bp.get("/<int:vuln_id>")
@api_login_required
def get_vuln(vuln_id):
    if _is_network():
        v = db.session.get(IPScanVulnerability, vuln_id)
        if v is None:
            return jsonify(error="Finding not found."), 404
        return jsonify(vulnerability=_network_to_dict(v))
    v = db.session.get(Vulnerability, vuln_id)
    if v is None:
        return jsonify(error="Finding not found."), 404
    return jsonify(vulnerability={**v.to_dict(), "source": SOURCE_WEB})


@bp.route("/<int:vuln_id>", methods=["PATCH", "PUT"])
@api_login_required
def update_vuln(vuln_id):
    network = _is_network()
    v = db.session.get(IPScanVulnerability if network else Vulnerability, vuln_id)
    if v is None:
        return jsonify(error="Finding not found."), 404
    data = request.get_json(silent=True) or {}
    if "status" in data:
        if data["status"] not in STATUSES:
            return jsonify(error=f"Invalid status. Use one of: {', '.join(STATUSES)}"), 400
        v.status = data["status"]
    # Network findings have no notes column; ignore it rather than erroring.
    if "notes" in data and not network:
        v.notes = str(data["notes"])[:4000]
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not update finding: {exc}"), 500
    payload = _network_to_dict(v) if network else {**v.to_dict(), "source": SOURCE_WEB}
    return jsonify(message="Finding updated.", vulnerability=payload)


@bp.delete("/<int:vuln_id>")
@api_login_required
def delete_vuln(vuln_id):
    network = _is_network()
    v = db.session.get(IPScanVulnerability if network else Vulnerability, vuln_id)
    if v is None:
        return jsonify(error="Finding not found."), 404
    try:
        db.session.delete(v)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not delete finding: {exc}"), 500
    return jsonify(message="Finding deleted.")
