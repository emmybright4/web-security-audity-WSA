"""AI Assistant API. Uses real findings from the DB; fails honestly when AI is not configured."""
from flask import Blueprint, current_app, jsonify, request

from ..models import Scan, Vulnerability
from ..services.engines import ai_service
from ._api_guard import api_login_required

bp = Blueprint("ai", __name__, url_prefix="/api/ai")


def _config():
    return current_app.config


@bp.get("/status")
@api_login_required
def status():
    ok, detail = ai_service.availability(_config())
    return jsonify(configured=ok, detail=detail)


@bp.post("/analyze")
@api_login_required
def analyze():
    ok, detail = ai_service.availability(_config())
    if not ok:
        return jsonify(error=detail, configured=False), 400

    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    question = (data.get("question") or "").strip()[:2000]

    query = Vulnerability.query
    if scan_id:
        if db.session.get(Scan, scan_id) is None:
            return jsonify(error=f"Scan #{scan_id} not found."), 404
        query = query.filter(Vulnerability.scan_id == scan_id)
    findings = query.order_by(Vulnerability.created_at.desc()).limit(80).all()

    try:
        answer = ai_service.analyze_findings(_config(), [f.to_dict() for f in findings],
                                             question=question or None)
    except ai_service.AIError as exc:
        return jsonify(error=str(exc), configured=False), 400
    except Exception as exc:
        current_app.logger.exception("AI analysis failed")
        return jsonify(error=f"AI request failed: {exc}"), 502

    return jsonify(answer=answer, findings_used=len(findings),
                  scan_id=scan_id, question=question)
