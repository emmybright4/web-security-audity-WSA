"""Report generation API: create PDFs from real scans, list, serve, delete."""
import os

from flask import Blueprint, current_app, jsonify, request, send_file
from sqlalchemy import desc

from ..extensions import db
from ..models import Report, Scan, Vulnerability
from ..services.report_service import generate_report

bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@bp.get("")
def list_reports():
    try:
        rows = Report.query.order_by(desc(Report.generated_at)).limit(200).all()
        return jsonify(reports=[r.to_dict() for r in rows])
    except Exception as exc:
        return jsonify(error=f"Failed to list reports: {exc}"), 500


@bp.post("/generate")
def generate():
    data = request.get_json(silent=True) or {}
    scan_id = data.get("scan_id")
    scan = db.session.get(Scan, scan_id) if scan_id else None
    if scan is None:
        return jsonify(error="A valid scan_id is required to generate a report."), 400

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    name = (data.get("report_name") or "").strip() or None
    try:
        path = generate_report(scan, vulns, current_app.config["REPORTS_DIR"], report_name=name)
    except Exception as exc:
        current_app.logger.exception("report generation failed")
        return jsonify(error=f"Report generation failed: {exc}"), 500

    report = Report(scan_id=scan.id, report_name=os.path.basename(path), report_path=path)
    db.session.add(report)
    db.session.commit()
    return jsonify(message="Report generated.", report=report.to_dict()), 201


@bp.get("/<int:report_id>/download")
def download(report_id):
    r = db.session.get(Report, report_id)
    if r is None or not os.path.exists(r.report_path):
        return jsonify(error="Report file not found."), 404
    return send_file(r.report_path, as_attachment=True, mimetype="application/pdf",
                     download_name=r.report_name)


@bp.get("/<int:report_id>/view")
def view(report_id):
    r = db.session.get(Report, report_id)
    if r is None or not os.path.exists(r.report_path):
        return jsonify(error="Report file not found."), 404
    return send_file(r.report_path, mimetype="application/pdf")


@bp.delete("/<int:report_id>")
def delete(report_id):
    r = db.session.get(Report, report_id)
    if r is None:
        return jsonify(error="Report not found."), 404
    try:
        if os.path.exists(r.report_path):
            os.remove(r.report_path)
        db.session.delete(r)
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not delete report: {exc}"), 500
    return jsonify(message="Report deleted.")
