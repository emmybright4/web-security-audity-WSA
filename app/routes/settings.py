"""Settings API: persists runtime settings in the DB (Settings table)."""
from flask import Blueprint, current_app, jsonify, request

from ..extensions import db
from ..models import Setting

bp = Blueprint("settings", __name__, url_prefix="/api/settings")

ALLOWED_KEYS = {"default_scan_type", "polling_fallback_seconds", "max_pages",
                "notifications_enabled", "confirm_authorization", "theme"}


@bp.get("")
def get_settings():
    rows = Setting.query.all()
    values = {r.key: r.value for r in rows}
    values.setdefault("default_scan_type", "quick")
    values.setdefault("polling_fallback_seconds",
                      current_app.config.get("POLLING_FALLBACK_SECONDS", 4))
    values.setdefault("max_pages", 12)
    values.setdefault("notifications_enabled", True)
    values.setdefault("confirm_authorization", True)
    return jsonify(settings=values)


@bp.put("")
def put_settings():
    data = request.get_json(silent=True) or {}
    updated = {}
    for key, value in data.items():
        if key not in ALLOWED_KEYS:
            continue
        row = db.session.get(Setting, key)
        if row is None:
            row = Setting(key=key)
            db.session.add(row)
        row.value = value
        updated[key] = value
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not save settings: {exc}"), 500
    return jsonify(message=f"Saved {len(updated)} setting(s).", settings=updated)
