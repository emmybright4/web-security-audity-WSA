"""Target management API (targets = distinct scan targets)."""
from collections import defaultdict

from flask import Blueprint, jsonify, request
from sqlalchemy import desc, func

from ..extensions import db
from ..models import Scan, Vulnerability
from ._api_guard import api_login_required

bp = Blueprint("targets", __name__, url_prefix="/api/targets")


@bp.get("")
@api_login_required
def list_targets():
    try:
        scans = Scan.query.order_by(desc(Scan.created_at)).all()
        targets = {}
        for s in scans:
            t = targets.setdefault(s.target_url, {
                "target_url": s.target_url, "scan_count": 0, "last_scan_at": None,
                "last_status": None, "findings": defaultdict(int),
            })
            t["scan_count"] += 1
            if t["last_scan_at"] is None and s.created_at:
                t["last_scan_at"] = s.created_at
                t["last_status"] = s.status
        for row in (db.session.query(Vulnerability.target_url, Vulnerability.severity,
                                     func.count(Vulnerability.id))
                    .group_by(Vulnerability.target_url, Vulnerability.severity).all()):
            if row[0] in targets:
                g = ("high" if row[1] in ("high", "critical")
                     else "medium" if row[1] == "medium"
                     else "low" if row[1] == "low" else "informational")
                targets[row[0]]["findings"][g] += row[2]
        out = []
        for t in targets.values():
            f = t.pop("findings")
            t["findings"] = dict(f)
            t["total_findings"] = sum(f.values())
            t["last_scan_at"] = t["last_scan_at"].isoformat() if t["last_scan_at"] else None
            out.append(t)
        return jsonify(targets=out)
    except Exception as exc:
        return jsonify(error=f"Failed to load targets: {exc}"), 500


@bp.get("/<path:target_url>/scans")
@api_login_required
def target_scans(target_url):
    try:
        scans = (Scan.query.filter_by(target_url=target_url)
                 .order_by(desc(Scan.created_at)).limit(100).all())
        return jsonify(scans=[s.to_dict() for s in scans])
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@bp.post("/validate")
@api_login_required
def validate_target():
    from ..utils import is_local_target, is_valid_url, normalize_url
    data = request.get_json(silent=True) or {}
    url = normalize_url(str(data.get("target_url", "")))
    if not is_valid_url(url):
        return jsonify(valid=False, reason="Not a valid http(s) URL."), 400
    return jsonify(valid=True, local=is_local_target(url), normalized=url)
