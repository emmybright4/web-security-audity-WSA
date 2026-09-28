"""Scan lifecycle API: create, list, detail, cancel, delete."""
import logging

from flask import Blueprint, current_app, jsonify, request
from flask_login import current_user
from sqlalchemy import desc

from ..extensions import db
from ..models import Scan, ScanTemplate, Vulnerability
from ..services import scanner
from ..utils import is_valid_url, normalize_url
from ._api_guard import api_login_required

log = logging.getLogger("wsa.scans")

bp = Blueprint("scans", __name__, url_prefix="/api/scans")

VALID_TYPES = {"quick", "full", "custom"}


@bp.get("")
@api_login_required
def list_scans():
    try:
        limit = min(int(request.args.get("limit", 50)), 200)
        scans = Scan.query.order_by(desc(Scan.created_at)).limit(limit).all()
        return jsonify(scans=[s.to_dict() for s in scans])
    except Exception as exc:
        log.exception("list scans failed")
        return jsonify(error=f"Failed to list scans: {exc}"), 500


@bp.post("")
@api_login_required
def create_scan():
    data = request.get_json(silent=True) or request.form.to_dict()
    return _create_scan_from_data(data or {})


def _parse_options(data):
    def as_bool(key, default=False):
        v = data.get(key, default)
        if isinstance(v, bool):
            return v
        return str(v).lower() in ("true", "1", "yes", "on")

    return {
        "playwright_enabled": as_bool("playwright_enabled"),
        "zap_enabled": as_bool("zap_enabled"),
        "zap_mode": str(data.get("zap_mode", "active")),
        "nuclei_enabled": as_bool("nuclei_enabled"),
        "nuclei_severity": str(data.get("nuclei_severity", "low,medium,high,critical")),
        "sqli_enabled": as_bool("sqli_enabled"),
        "sqli_mode": str(data.get("sqli_mode", "builtin")),
        "ai_assist": as_bool("ai_assist"),
        "auth_enabled": as_bool("auth_enabled"),
        "auth_username": str(data.get("auth_username", "")),
        "auth_password": str(data.get("auth_password", "")),
        "max_pages": int(data.get("max_pages") or 12),
        "policy": str(data.get("policy", "balanced")),
        "engines_requested": [e for e, on in (
            ("playwright", as_bool("playwright_enabled")),
            ("zap", as_bool("zap_enabled")),
            ("nuclei", as_bool("nuclei_enabled")),
            ("sqli", as_bool("sqli_enabled")),
            ("builtin", True),
        ) if on],
    }


def _create_scan_from_data(data):
    if not data:
        return jsonify(error="Request body is required."), 400

    target = normalize_url(str(data.get("target_url", "")))
    if not is_valid_url(target):
        return jsonify(error="Invalid target URL. Use a full URL like https://example.com"), 400

    scan_type = str(data.get("scan_type", "quick")).lower()
    if scan_type not in VALID_TYPES:
        return jsonify(error=f"Invalid scan type '{scan_type}'. Use quick, full or custom."), 400

    if str(data.get("authorized", "")).lower() not in ("true", "1", "yes", "on"):
        return jsonify(error="You must confirm you are authorized to audit this target."), 400

    options = _parse_options(data)

    try:
        scan = Scan(target_url=target, scan_type=scan_type, status="pending", progress=0,
                    options=options, current_step="Queued",
                    user_id=getattr(current_user, "row", None) and current_user.row.id)
        db.session.add(scan)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        log.exception("scan create failed")
        return jsonify(error=f"Could not create scan record: {exc}"), 500

    try:
        scanner.start_scan(current_app._get_current_object(), scan.id)
    except Exception as exc:
        log.exception("scan start failed")
        scan.status = "failed"
        scan.error_message = f"Failed to launch scan worker: {exc}"
        db.session.commit()
        return jsonify(error=scan.error_message, scan=scan.to_dict()), 500

    return jsonify(message="Scan started.", scan=scan.to_dict()), 201


@bp.get("/<int:scan_id>")
@api_login_required
def get_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify(error="Scan not found."), 404
    vulns = (Vulnerability.query.filter_by(scan_id=scan_id)
             .order_by(Vulnerability.created_at.desc()).all())
    return jsonify(scan=scan.to_dict(), vulnerabilities=[v.to_dict() for v in vulns])


@bp.post("/<int:scan_id>/cancel")
@api_login_required
def cancel_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify(error="Scan not found."), 404
    if scan.status not in ("pending", "running"):
        return jsonify(error=f"Scan is already {scan.status}; cannot cancel."), 400
    scanner.request_cancel(scan_id)
    return jsonify(message="Cancellation requested.", scan=scan.to_dict())


@bp.delete("/<int:scan_id>")
@api_login_required
def delete_scan(scan_id):
    scan = db.session.get(Scan, scan_id)
    if scan is None:
        return jsonify(error="Scan not found."), 404
    scanner.request_cancel(scan_id)
    try:
        db.session.delete(scan)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not delete scan: {exc}"), 500
    return jsonify(message=f"Scan #{scan_id} deleted.")


@bp.post("/from-template/<int:template_id>")
@api_login_required
def from_template(template_id):
    tpl = db.session.get(ScanTemplate, template_id)
    if tpl is None:
        return jsonify(error="Template not found."), 404
    body = request.get_json(silent=True) or {}
    merged = {**dict(tpl.options or {}), **body}
    # launching from a saved template implies authorization was acknowledged,
    # but an explicit false still blocks.
    if "authorized" not in merged:
        merged["authorized"] = "true"
    return _create_scan_from_data(merged)
