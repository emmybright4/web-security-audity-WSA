"""PDF report generation using ReportLab.

Reports contain ONLY real data pulled from the database: executive summary,
scan details, severity breakdown, findings table and remediation guidance.
"""
import logging
import os
from datetime import datetime

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import mm
from reportlab.platypus import (KeepTogether, PageBreak, Paragraph, SimpleDocTemplate,
                                Spacer, Table, TableStyle)

log = logging.getLogger("wsa.reports")

NAVY = colors.HexColor("#0f2a5c")
BLUE = colors.HexColor("#1a56db")
LIGHT = colors.HexColor("#eef2f9")
SEV_COLORS = {
    "high": colors.HexColor("#dc2626"),
    "medium": colors.HexColor("#f59e0b"),
    "low": colors.HexColor("#16a34a"),
    "informational": colors.HexColor("#2563eb"),
}


def generate_report(scan, vulnerabilities, reports_dir, report_name=None):
    """Build the PDF for one scan. Returns the absolute file path."""
    os.makedirs(reports_dir, exist_ok=True)
    stamp = datetime.utcnow().strftime("%Y%m%d-%H%M%S")
    safe_name = report_name or f"WSA-Report-Scan{scan.id}-{stamp}"
    if not safe_name.lower().endswith(".pdf"):
        safe_name += ".pdf"
    path = os.path.join(reports_dir, safe_name)

    styles = getSampleStyleSheet()
    h1 = ParagraphStyle("H1", parent=styles["Title"], textColor=NAVY, fontSize=22, spaceAfter=4)
    h2 = ParagraphStyle("H2", parent=styles["Heading2"], textColor=NAVY, spaceBefore=14, spaceAfter=6)
    body = ParagraphStyle("Body", parent=styles["BodyText"], fontSize=9.5, leading=13)
    small = ParagraphStyle("Small", parent=styles["BodyText"], fontSize=8, leading=10,
                           textColor=colors.HexColor("#4b5563"))
    slogan = ParagraphStyle("Slogan", parent=styles["Normal"], alignment=TA_CENTER,
                            textColor=BLUE, fontSize=10, spaceBefore=2)

    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for v in vulnerabilities:
        sev = v.severity if v.severity in counts else ("informational" if v.severity in ("info",) else "medium" if v.severity == "critical" else "low" if v.severity not in counts else v.severity)
        if v.severity in counts:
            counts[v.severity] += 1
        elif v.severity == "critical":
            counts["high"] += 1
        elif v.severity == "info":
            counts["informational"] += 1

    story = []

    # ---- cover -------------------------------------------------------------
    story.append(Spacer(1, 30 * mm))
    story.append(Paragraph("WSA - Web Security Auditing", h1))
    story.append(Paragraph("Discover. Analyze. Secure.", slogan))
    story.append(Spacer(1, 10 * mm))
    cover = Table([
        ["Report", safe_name],
        ["Target", scan.target_url],
        ["Scan Type", scan.scan_type.title()],
        ["Scan Status", scan.status.title()],
        ["Scan ID", f"#{scan.id}"],
        ["Started", scan.started_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.started_at else "-"],
        ["Completed", scan.completed_at.strftime("%Y-%m-%d %H:%M:%S UTC") if scan.completed_at else "-"],
        ["Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC")],
    ], colWidths=[45 * mm, 105 * mm])
    cover.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), LIGHT),
        ("TEXTCOLOR", (0, 0), (0, -1), NAVY),
        ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("VALIGN", (0, 0), (-1, -1), "MIDDLE"),
        ("TOPPADDING", (0, 0), (-1, -1), 5),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 5),
    ]))
    story.append(cover)
    story.append(PageBreak())

    # ---- executive summary ----------------------------------------------------
    story.append(Paragraph("1. Executive Summary", h2))
    total = len(vulnerabilities)
    risk = "HIGH" if counts["high"] else ("MEDIUM" if counts["medium"] else
                                          ("LOW" if counts["low"] else "INFORMATIONAL"))
    summary_text = (
        f"A {scan.scan_type} security audit was performed against <b>{scan.target_url}</b> using the "
        f"WSA - Web Security Auditing platform. The scan completed with status "
        f"<b>{scan.status}</b> and produced <b>{total}</b> finding(s): "
        f"<b>{counts['high']}</b> high, <b>{counts['medium']}</b> medium, "
        f"<b>{counts['low']}</b> low and <b>{counts['informational']}</b> informational. "
        f"Based on the observed severities, the overall risk rating of this target is "
        f"<b>{risk}</b>."
    )
    if scan.error_message:
        summary_text += f"<br/><br/><b>Scan note:</b> {scan.error_message}"
    story.append(Paragraph(summary_text, body))

    story.append(Paragraph("Severity Breakdown", h2))
    sev_tbl = Table([
        ["Severity", "Count", "Share"],
        ["High", str(counts["high"]), f"{_share(counts['high'], total)}%"],
        ["Medium", str(counts["medium"]), f"{_share(counts['medium'], total)}%"],
        ["Low", str(counts["low"]), f"{_share(counts['low'], total)}%"],
        ["Informational", str(counts["informational"]), f"{_share(counts['informational'], total)}%"],
        ["Total", str(total), "100%"],
    ], colWidths=[50 * mm, 30 * mm, 30 * mm])
    sev_tbl.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (-1, 0), NAVY),
        ("TEXTCOLOR", (0, 0), (-1, 0), colors.white),
        ("FONTNAME", (0, 0), (-1, 0), "Helvetica-Bold"),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.4, colors.HexColor("#cbd5e1")),
        ("ROWBACKGROUNDS", (0, 1), (-1, -2), [colors.white, LIGHT]),
        ("BACKGROUND", (0, -1), (-1, -1), LIGHT),
        ("FONTNAME", (0, -1), (-1, -1), "Helvetica-Bold"),
        ("TOPPADDING", (0, 0), (-1, -1), 4),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 4),
    ]))
    story.append(sev_tbl)

    # ---- scan details ------------------------------------------------------------
    story.append(Paragraph("2. Scan Details", h2))
    tools_used = sorted({v.detected_by for v in vulnerabilities}) or ["WSA Built-in Scanner"]
    details = [
        f"Target URL: {scan.target_url}",
        f"Scan type: {scan.scan_type}",
        f"Scan ID: {scan.id}",
        f"Final status: {scan.status} ({scan.progress}% complete)",
        f"Detection tools that reported findings: {', '.join(tools_used)}",
        f"Duration: {scan.duration_seconds if scan.duration_seconds is not None else 'n/a'} seconds",
    ]
    for line in details:
        story.append(Paragraph(f"&bull; {line}", body))

    # ---- findings ---------------------------------------------------------------
    story.append(Paragraph("3. Findings", h2))
    if not vulnerabilities:
        story.append(Paragraph(
            "No vulnerabilities were recorded for this scan. "
            "This may mean the target had no detectable issues, or that no scanner engines "
            "were enabled/configured for the audit.", body))
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    for i, v in enumerate(sorted(vulnerabilities, key=lambda x: order.get(x.severity, 5)), start=1):
        color = SEV_COLORS.get(v.severity, SEV_COLORS["informational"])
        head = Paragraph(
            f"<font color='{color.hexval()[2:] if False else '#' + color.hexval()[2:]}'><b>"
            f"#{i} [{v.severity.upper()}] {v.name}</b></font>",
            ParagraphStyle("FH", parent=body, fontSize=10.5, spaceBefore=10))
        rows = [
            ["Severity", v.severity.upper()],
            ["Confidence", (v.confidence or "n/a").upper()],
            ["Target", v.target_url or scan.target_url],
            ["Endpoint", v.url or "-"],
            ["Detected by", v.detected_by],
            ["Status", (v.status or "open").upper()],
            ["Created", v.created_at.strftime("%Y-%m-%d %H:%M UTC") if v.created_at else "-"],
        ]
        t = Table(rows, colWidths=[30 * mm, 130 * mm])
        t.setStyle(TableStyle([
            ("BACKGROUND", (0, 0), (0, -1), LIGHT),
            ("FONTNAME", (0, 0), (0, -1), "Helvetica-Bold"),
            ("FONTSIZE", (0, 0), (-1, -1), 8),
            ("GRID", (0, 0), (-1, -1), 0.3, colors.HexColor("#cbd5e1")),
            ("TOPPADDING", (0, 0), (-1, -1), 3),
            ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ]))
        block = [head, t,
                 Paragraph(f"<b>Description:</b> {v.description or 'n/a'}", small),
                 Paragraph(f"<b>Evidence:</b> {v.evidence or 'n/a'}", small),
                 Paragraph(f"<b>Remediation:</b> {v.remediation or 'n/a'}", small)]
        story.append(KeepTogether(block))

    # ---- recommendations ------------------------------------------------------------
    story.append(Paragraph("4. Remediation Recommendations", h2))
    recs = _recommendations(vulnerabilities)
    if recs:
        for r in recs:
            story.append(Paragraph(f"&bull; {r}", body))
    else:
        story.append(Paragraph("No remediation items - no findings recorded.", body))

    story.append(Spacer(1, 12 * mm))
    story.append(Paragraph(
        "This report was generated automatically by WSA - Web Security Auditing from real scan data. "
        "It is intended for the authorized owner of the audited target.", small))

    doc = SimpleDocTemplate(path, pagesize=A4, leftMargin=18 * mm, rightMargin=18 * mm,
                            topMargin=16 * mm, bottomMargin=16 * mm,
                            title=f"WSA Security Report - {scan.target_url}")
    doc.build(story)
    log.info("Report generated: %s", path)
    return path


def _share(part, total):
    return round(100 * part / total, 1) if total else "0.0"


def render_html_report(scan, vulnerabilities):
    """HTML twin of :func:`generate_report`, built from the same DB rows."""
    from datetime import datetime
    from markupsafe import escape

    order = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4, "informational": 4}
    rows = sorted(vulnerabilities, key=lambda v: order.get(v.severity, 5))
    counts = {"high": 0, "medium": 0, "low": 0, "informational": 0}
    for v in rows:
        if v.severity in ("high", "critical"):
            counts["high"] += 1
        elif v.severity == "medium":
            counts["medium"] += 1
        elif v.severity == "low":
            counts["low"] += 1
        else:
            counts["informational"] += 1

    facts = [("Target", scan.target_url), ("Scan ID", f"#{scan.id}"),
             ("Scan type", scan.scan_type), ("Status", scan.status),
             ("Started", scan.started_at.strftime("%Y-%m-%d %H:%M UTC") if scan.started_at else "-"),
             ("Completed", scan.completed_at.strftime("%Y-%m-%d %H:%M UTC") if scan.completed_at else "-"),
             ("Generated", datetime.utcnow().strftime("%Y-%m-%d %H:%M:%S UTC"))]
    fact_html = "".join(
        f'<tr><th style="text-align:left;padding:6px 14px 6px 0;color:#64748b;'
        f'font-weight:600">{escape(str(k))}</th>'
        f'<td style="padding:6px 0">{escape(str(v))}</td></tr>' for k, v in facts)

    if rows:
        finding_html = "".join(
            f'<tr>'
            f'<td style="padding:6px 8px;border-top:1px solid #e2e8f0">{i}</td>'
            f'<td style="padding:6px 8px;border-top:1px solid #e2e8f0">'
            f'<span style="font-weight:700;color:'
            f'{SEV_COLORS.get(v.severity, SEV_COLORS["informational"]).hexval()[2:]}">'
            f'{escape((v.severity or "").upper())}</span></td>'
            f'<td style="padding:6px 8px;border-top:1px solid #e2e8f0">'
            f'{escape(v.name or "")}</td>'
            f'<td style="padding:6px 8px;border-top:1px solid #e2e8f0">'
            f'{escape(v.url or v.target_url or "")}</td>'
            f'<td style="padding:6px 8px;border-top:1px solid #e2e8f0">'
            f'{escape(v.detected_by or "")}</td>'
            f'<td style="padding:6px 8px;border-top:1px solid #e2e8f0">'
            f'{escape(v.remediation or "")}</td></tr>'
            for i, v in enumerate(rows, start=1))
    else:
        finding_html = ('<tr><td colspan="6" style="padding:12px 8px;color:#64748b">'
                        'No vulnerabilities were recorded for this scan.</td></tr>')

    return f"""<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<title>WSA security report - scan #{scan.id}</title></head>
<body style="margin:0;padding:28px;background:#f1f5f9;font-family:Segoe UI,Roboto,Arial,sans-serif;color:#0f172a">
<div style="max-width:900px;margin:0 auto;background:#fff;border:1px solid #e2e8f0;border-radius:12px;padding:26px">
  <h1 style="margin:0;font-size:22px;color:#0f2a5c">WSA &mdash; Web Security Auditing</h1>
  <p style="margin:4px 0 18px;color:#1a56db;font-weight:600">Discover. Analyze. Secure.</p>
  <h2 style="font-size:17px;margin:22px 0 6px">Scan details</h2>
  <table style="width:100%;font-size:13px;border-collapse:collapse">{fact_html}</table>
  <h2 style="font-size:17px;margin:22px 0 6px">Severity breakdown</h2>
  <p style="margin:0;font-size:13px;color:#334155">
    High/Critical: {counts['high']} &middot; Medium: {counts['medium']} &middot;
    Low: {counts['low']} &middot; Informational: {counts['informational']} &middot;
    Total: {len(rows)}
  </p>
  <h2 style="font-size:17px;margin:22px 0 6px">Findings</h2>
  <table style="width:100%;font-size:12.5px;border-collapse:collapse">
    <thead><tr style="background:#0f2a5c;color:#fff">
      <th style="padding:7px 8px;text-align:left">#</th>
      <th style="padding:7px 8px;text-align:left">Severity</th>
      <th style="padding:7px 8px;text-align:left">Finding</th>
      <th style="padding:7px 8px;text-align:left">Endpoint</th>
      <th style="padding:7px 8px;text-align:left">Detected by</th>
      <th style="padding:7px 8px;text-align:left">Remediation</th>
    </tr></thead>
    <tbody>{finding_html}</tbody>
  </table>
  <p style="margin:22px 0 0;font-size:12px;color:#64748b">
    Generated automatically by WSA from real scan data, for the authorised owner of the
    audited target.</p>
</div></body></html>"""


def _recommendations(vulns):
    seen, out = set(), []
    for v in vulns:
        text = (v.remediation or "").strip()
        if text and text.lower() not in seen:
            seen.add(text.lower())
            out.append(text)
    return out[:15]
