"""Report generation API: create PDFs from real scans, list, serve, delete."""
import os

from flask import Blueprint, current_app, jsonify, request, send_file
from sqlalchemy import desc

from ..extensions import db
from ..models import Report, Scan, Vulnerability
from ..services import notification_service
from ..services.report_service import generate_report, render_html_report
from ._api_guard import api_login_required
from .auth import current_row

bp = Blueprint("reports", __name__, url_prefix="/api/reports")


@bp.get("")
@api_login_required
def list_reports():
    try:
        rows = Report.query.order_by(desc(Report.generated_at)).limit(200).all()
        return jsonify(reports=[r.to_dict() for r in rows])
    except Exception as exc:
        return jsonify(error=f"Failed to list reports: {exc}"), 500


@bp.post("/generate")
@api_login_required
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
@api_login_required
def download(report_id):
    r = db.session.get(Report, report_id)
    if r is None or not os.path.exists(r.report_path):
        return jsonify(error="Report file not found."), 404
    return send_file(r.report_path, as_attachment=True, mimetype="application/pdf",
                     download_name=r.report_name)


@bp.get("/<int:report_id>/view")
@api_login_required
def view(report_id):
    r = db.session.get(Report, report_id)
    if r is None or not os.path.exists(r.report_path):
        return jsonify(error="Report file not found."), 404
    return send_file(r.report_path, mimetype="application/pdf")


@bp.delete("/<int:report_id>")
@api_login_required
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


# ------------------------------------------------------- delivery ----------

@bp.get("/recipients")
@api_login_required
def report_recipients():
    """Only verified addresses may ever receive report content."""
    user = current_row()
    return jsonify(recipients=notification_service.verified_recipients(user),
                   scans=[{"id": s.id, "target_url": s.target_url, "status": s.status}
                          for s in Scan.query.order_by(desc(Scan.created_at)).limit(50).all()])


@bp.post("/email")
@api_login_required
def email_report():
    """Generate (if needed) and email a report to verified recipients."""
    data = request.get_json(silent=True) or {}
    scan = db.session.get(Scan, data.get("scan_id")) if data.get("scan_id") else None
    if scan is None:
        return jsonify(error="A valid scan_id is required."), 400
    fmt = str(data.get("format") or "pdf").strip().lower()
    if fmt not in ("pdf", "html"):
        return jsonify(error="Report format must be pdf or html."), 400

    allowed = {entry["email"].lower()
               for entry in notification_service.verified_recipients(current_row())}
    requested = data.get("recipients")
    if isinstance(requested, str):
        requested = [requested]
    chosen = []
    rejected = []
    for entry in requested or []:
        address = (str(entry or "").strip().lower())
        if not address:
            continue
        if address in allowed:
            chosen.append({"email": address})
        else:
            rejected.append(address)
    if not chosen:
        return jsonify(error="Choose at least one verified recipient.",
                       rejected=rejected), 400

    vulns = Vulnerability.query.filter_by(scan_id=scan.id).all()
    name = (data.get("report_name") or "").strip() or None
    if fmt == "html":
        html = render_html_report(scan, vulns)
        path = _write_html(scan, html)
    else:
        try:
            path = generate_report(scan, vulns, current_app.config["REPORTS_DIR"],
                                   report_name=name)
        except Exception as exc:
            current_app.logger.exception("report generation failed")
            return jsonify(error=f"Report generation failed: {exc}"), 500

    report = Report(scan_id=scan.id, report_name=os.path.basename(path), report_path=path)
    db.session.add(report)
    db.session.commit()

    rows = notification_service.deliver_report(scan, path, chosen,
                                               report_name=os.path.basename(path), fmt=fmt)
    delivered = [r.recipient for r in rows if getattr(r, "status", "") == "sent"]
    if not delivered:
        return jsonify(error="The report could not be delivered. Check the mail configuration "
                             "in Settings and the email history for details.",
                       rejected=rejected), 502
    return jsonify(message=f"Report sent to {len(delivered)} verified recipient(s).",
                   sent_to=delivered, rejected=rejected, report=report.to_dict())


def _write_html(scan, html):
    directory = current_app.config["REPORTS_DIR"]
    os.makedirs(directory, exist_ok=True)
    path = os.path.join(directory, f"wsa_scan_{scan.id}_report.html")
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(html)
    return path
