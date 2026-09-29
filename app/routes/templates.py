"""Scan template CRUD API."""
from flask import Blueprint, jsonify, request

from ..extensions import db
from ..models import ScanTemplate
from ._api_guard import api_login_required

bp = Blueprint("templates", __name__, url_prefix="/api/templates")


@bp.get("")
@api_login_required
def list_templates():
    try:
        rows = ScanTemplate.query.order_by(ScanTemplate.created_at.desc()).all()
        return jsonify(templates=[t.to_dict() for t in rows])
    except Exception as exc:
        return jsonify(error=f"Failed to load templates: {exc}"), 500


@bp.post("")
@api_login_required
def create_template():
    data = request.get_json(silent=True) or {}
    name = (data.get("name") or "").strip()
    if not name:
        return jsonify(error="Template name is required."), 400
    if len(name) > 120:
        return jsonify(error="Template name is too long (max 120 characters)."), 400

    # keep only known option keys to avoid junk
    allowed = {"playwright_enabled", "zap_enabled", "zap_mode", "nuclei_enabled",
               "nuclei_severity", "sqli_enabled", "sqli_mode", "ai_assist",
               "auth_enabled", "auth_username", "max_pages", "policy", "scan_type"}
    options = {k: v for k, v in data.items() if k in allowed}

    try:
        tpl = ScanTemplate(name=name, description=(data.get("description") or "")[:500],
                           options=options)
        db.session.add(tpl)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not save template: {exc}"), 500
    return jsonify(message="Template saved.", template=tpl.to_dict()), 201


@bp.delete("/<int:template_id>")
@api_login_required
def delete_template(template_id):
    tpl = db.session.get(ScanTemplate, template_id)
    if tpl is None:
        return jsonify(error="Template not found."), 404
    try:
        db.session.delete(tpl)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not delete template: {exc}"), 500
    return jsonify(message="Template deleted.")
