"""Vulnerability findings API: list/filter/search/sort, update status, notes, delete."""
from flask import Blueprint, jsonify, request
from sqlalchemy import or_

from ..extensions import db
from ..models import Vulnerability

bp = Blueprint("vulnerabilities", __name__, url_prefix="/api/vulnerabilities")

SEVERITIES = ("high", "medium", "low", "informational", "critical", "info")
STATUSES = ("open", "in_review", "resolved", "false_positive")


@bp.get("")
def list_vulns():
    try:
        q = Vulnerability.query

        search = (request.args.get("search") or "").strip()
        if search:
            like = f"%{search}%"
            q = q.filter(or_(Vulnerability.name.ilike(like),
                             Vulnerability.description.ilike(like),
                             Vulnerability.url.ilike(like),
                             Vulnerability.target_url.ilike(like)))

        severity = (request.args.get("severity") or "").strip().lower()
        if severity:
            if severity == "high":
                q = q.filter(Vulnerability.severity.in_(("high", "critical")))
            elif severity == "info":
                q = q.filter(Vulnerability.severity.in_(("informational", "info")))
            else:
                q = q.filter(Vulnerability.severity == severity)

        target = (request.args.get("target") or "").strip()
        if target:
            q = q.filter(Vulnerability.target_url.ilike(f"%{target}%"))

        scan_id = request.args.get("scan_id", type=int)
        if scan_id:
            q = q.filter(Vulnerability.scan_id == scan_id)

        status = (request.args.get("status") or "").strip()
        if status:
            q = q.filter(Vulnerability.status == status)

        sort = request.args.get("sort", "newest")
        if sort == "oldest":
            q = q.order_by(Vulnerability.created_at.asc())
        elif sort == "severity":
            q = q.order_by(Vulnerability.created_at.desc())
        elif sort == "name":
            q = q.order_by(Vulnerability.name.asc())
        else:
            q = q.order_by(Vulnerability.created_at.desc())

        limit = min(int(request.args.get("limit", 200)), 1000)
        rows = q.limit(limit).all()
        return jsonify(vulnerabilities=[v.to_dict() for v in rows],
                       count=len(rows))
    except Exception as exc:
        return jsonify(error=f"Failed to load findings: {exc}"), 500


@bp.get("/targets")
def distinct_targets():
    try:
        rows = (db.session.query(Vulnerability.target_url).distinct()
                .order_by(Vulnerability.target_url).all())
        return jsonify(targets=[r[0] for r in rows if r[0]])
    except Exception as exc:
        return jsonify(error=str(exc)), 500


@bp.get("/<int:vuln_id>")
def get_vuln(vuln_id):
    v = db.session.get(Vulnerability, vuln_id)
    if v is None:
        return jsonify(error="Finding not found."), 404
    return jsonify(vulnerability=v.to_dict())


@bp.route("/<int:vuln_id>", methods=["PATCH", "PUT"])
def update_vuln(vuln_id):
    v = db.session.get(Vulnerability, vuln_id)
    if v is None:
        return jsonify(error="Finding not found."), 404
    data = request.get_json(silent=True) or {}
    if "status" in data:
        if data["status"] not in STATUSES:
            return jsonify(error=f"Invalid status. Use one of: {', '.join(STATUSES)}"), 400
        v.status = data["status"]
    if "notes" in data:
        v.notes = str(data["notes"])[:4000]
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not update finding: {exc}"), 500
    return jsonify(message="Finding updated.", vulnerability=v.to_dict())


@bp.delete("/<int:vuln_id>")
def delete_vuln(vuln_id):
    v = db.session.get(Vulnerability, vuln_id)
    if v is None:
        return jsonify(error="Finding not found."), 404
    try:
        db.session.delete(v)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not delete finding: {exc}"), 500
    return jsonify(message="Finding deleted.")
