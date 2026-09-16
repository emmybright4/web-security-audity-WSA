"""Tools & Integrations API: real availability checks with DB persistence."""
from flask import Blueprint, current_app, jsonify

from ..extensions import db
from ..models import ToolIntegration
from ..services.tool_checker import check_all

bp = Blueprint("tools", __name__, url_prefix="/api/tools")


@bp.get("")
def list_tools():
    try:
        results = check_all(current_app)
        rows = ToolIntegration.query.all()
        return jsonify(tools=[r.to_dict() for r in rows], live=results)
    except Exception as exc:
        return jsonify(error=f"Tool check failed: {exc}"), 500


@bp.post("/test")
def test_all():
    try:
        results = check_all(current_app)
        connected = sum(1 for r in results.values() if r["status"] == "connected")
        return jsonify(message=f"Checked {len(results)} integrations - {connected} connected.",
                       live=results)
    except Exception as exc:
        return jsonify(error=f"Tool check failed: {exc}"), 500
