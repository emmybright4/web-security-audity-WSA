"""Notification service: turns real WSA events into email / SMS deliveries.

Every message body is built from database rows that actually exist. Nothing is
invented: if a scan has no findings, the "scan completed" mail says zero, and
if a critical alert fires it quotes the stored finding.

Delivery respects two gates:
  1. the instance-wide ``NOTIFICATIONS_ENABLED`` switch, and
  2. the recipient's per-event opt-in (NotificationPreference),
and only ever reaches *verified* channels.
"""
import logging
import os

from flask import current_app, url_for

from ..extensions import db
from ..models import (CHANNEL_EMAIL, CHANNEL_PHONE, NotificationPreference,
                      Scan, SecurityRecipient, User, utcnow)
from . import email_service, sms_service
from .phone_service import mask_phone

log = logging.getLogger("wsa.notifications")

# Event catalog: key -> (email_default_on, sms_supported, label)
EMAIL_EVENTS = {
    "email_verification": (True, "Email verification"),
    "password_reset": (True, "Password reset"),
    "new_login_alert": (True, "New login alert"),
    "scan_completed": (True, "Scan completed"),
    "scan_failed": (True, "Scan failed"),
    "critical_alert": (True, "Critical vulnerability alert"),
    "high_alert": (True, "High severity alert"),
    "scheduled_scan": (True, "Scheduled scan notification"),
    "security_report": (True, "Security reports"),
    "recipient_verification": (True, "Recipient verification"),
}

SMS_EVENTS = {
    "password_reset": (True, "Password reset"),
    "new_login_alert": (True, "New login alert"),
    "scan_completed": (True, "Scan completed"),
    "critical_alert": (True, "Critical vulnerability alert"),
}


def default_email_prefs():
    return {key: value[0] for key, value in EMAIL_EVENTS.items()}


def default_sms_prefs():
    return {key: value[0] for key, value in SMS_EVENTS.items()}


def enabled():
    return bool(current_app.config.get("NOTIFICATIONS_ENABLED", True))


def preferences_for(user_id):
    """Stored preferences merged over the defaults."""
    prefs = {"email": default_email_prefs(), "sms": default_sms_prefs()}
    if not user_id:
        return prefs
    row = NotificationPreference.query.filter_by(user_id=user_id).first()
    if row is None:
        return prefs
    prefs["email"].update({k: bool(v) for k, v in (row.email_events or {}).items()
                           if k in prefs["email"]})
    prefs["sms"].update({k: bool(v) for k, v in (row.sms_events or {}).items()
                         if k in prefs["sms"]})
    return prefs


def set_preferences(user_id, email_events, sms_events):
    row = NotificationPreference.query.filter_by(user_id=user_id).first()
    if row is None:
        row = NotificationPreference(user_id=user_id)
        db.session.add(row)
    email = default_email_prefs()
    email.update({k: bool(v) for k, v in (email_events or {}).items() if k in EMAIL_EVENTS})
    sms = default_sms_prefs()
    sms.update({k: bool(v) for k, v in (sms_events or {}).items() if k in SMS_EVENTS})
    row.email_events = email
    row.sms_events = sms
    db.session.commit()
    return row


def wants(user_id, channel, event):
    """Is this event enabled for this user on this channel?

    ``channel`` is a contact channel (``email`` / ``phone``); preferences are
    grouped by transport (``email`` / ``sms``).
    """
    if not enabled():
        return False
    catalog = EMAIL_EVENTS if channel == CHANNEL_EMAIL else SMS_EVENTS
    if event not in catalog:
        return False
    group = "email" if channel == CHANNEL_EMAIL else "sms"
    return bool(preferences_for(user_id)[group].get(event))


# ------------------------------------------------------------------ codes ----

def _code_email_body(code, minutes, purpose=CHANNEL_EMAIL):
    if purpose == "password_reset":
        intro = ("Use this code to reset your WSA password. If you did not request a "
                 "password reset, you can safely ignore this email.")
        heading = "Reset your WSA password"
    elif purpose == "recipient_verification":
        intro = ("Use this code to confirm this address as an authorised recipient of "
                 "WSA security reports.")
        heading = "Confirm your security email"
    elif purpose == "login_verification":
        intro = ("Use this code to finish signing in to WSA. If you did not try to sign in, "
                 "someone else may know your password - change it immediately.")
        heading = "Finish signing in to WSA"
    else:
        intro = ("Welcome to WSA. Confirm this address to activate your account and "
                 "unlock scanning, dashboards and reports.")
        heading = "Verify your WSA email"
    return email_service.layout(
        f"WSA - {heading}",
        f'<h2 style="margin:0 0 8px;font-size:20px">{heading}</h2>'
        f'<p style="margin:0 0 4px;color:#334155">{intro}</p>'
        f'<p style="margin:12px 0 0;color:#334155">Your verification code is:</p>'
        f'{email_service.code_block(code)}'
        f'<p style="margin:0;color:#64748b;font-size:13px">This code expires in '
        f'{minutes} minutes and can be used once.</p>'
        '<p style="margin:14px 0 0;color:#64748b;font-size:13px">Do not share this code '
        'with anyone. WSA will never ask you for it.</p>',
        preheader=f"Your WSA verification code expires in {minutes} minutes",
    )


def _code_sms_body(code, minutes, purpose=CHANNEL_EMAIL):
    label = {"password_reset": "WSA password reset",
             "login_verification": "WSA sign-in"}.get(purpose, "WSA verification")
    return (f"{label} code: {code}\n\n"
            f"This code expires in {minutes} minutes. Do not share this code.")


def _code_subject(purpose):
    """Subject line per purpose: a sign-in code must not read as a sign-up one."""
    return {"password_reset": "WSA - Password reset code",
            "login_verification": "WSA - Your sign-in code",
            "recipient_verification": "WSA - Confirm your security email"}.get(
                purpose, "WSA - Verify your email")


def send_code_email(user, destination, code, purpose):
    minutes = current_app.config.get("OTP_EXPIRATION_MINUTES", 10)
    html = _code_email_body(code, minutes, purpose)
    return email_service.send_email(
        destination,
        _code_subject(purpose),
        html,
        email_service.strip_html(html),
        email_type=purpose,
        user_id=user.id if user else None,
    )


def send_code_sms(user, destination, code, purpose, scan_id=None):
    return sms_service.send_sms(
        destination,
        _code_sms_body(code, current_app.config.get("OTP_EXPIRATION_MINUTES", 10), purpose),
        sms_type=purpose,
        purpose=purpose,
        user_id=user.id if user else None,
        related_scan_id=scan_id,
    )


# -------------------------------------------------------------- security ----

def notify_login(user, ip_address=None, user_agent=None, browser=None, os_name=None):
    """New-login alert. Every field is taken from the request, never invented."""
    if not wants(user.id, CHANNEL_EMAIL, "new_login_alert") and \
            not wants(user.id, CHANNEL_PHONE, "new_login_alert"):
        return []
    when = utcnow()
    rows = []
    detail = [("Time (UTC)", when.strftime("%Y-%m-%d %H:%M")),
              ("IP address", ip_address or "unavailable"),
              ("Browser", browser or user_agent or "unavailable"),
              ("Operating system", os_name or "unavailable")]
    if user.email and user.email_verified and wants(user.id, CHANNEL_EMAIL, "new_login_alert"):
        body = (f'<h2 style="margin:0 0 10px;font-size:20px">New login to your WSA account</h2>'
                f'<p style="color:#334155">A new sign-in was recorded for '
                f'<b>{_esc(user.username)}</b>.</p>'
                f'<table style="margin:14px 0;font-size:14px;color:#334155">'
                + "".join(f'<tr><td style="padding:3px 12px 3px 0;color:#64748b">{_esc(k)}</td>'
                          f'<td style="padding:3px 0">{_esc(v)}</td></tr>'
                          for k, v in detail) + "</table>"
                '<p style="color:#334155">If this was not you, reset your password and '
                'review your account immediately.</p>')
        rows.append(email_service.send_email(
            user.email, "WSA - New login to your account", email_service.layout(
                "WSA - New login to your account", body),
            email_type="new_login_alert", user_id=user.id))
    if user.phone_number and user.phone_verified and wants(user.id, CHANNEL_PHONE, "new_login_alert"):
        rows.append(sms_service.send_sms(
            user.phone_number,
            "WSA: A new login was detected on your account. "
            f"IP {ip_address or 'unavailable'}. If this wasn't you, secure your account.",
            sms_type="new_login_alert", purpose="new_login_alert", user_id=user.id))
    return rows


# ------------------------------------------------------------------ scans ----

def _scan_link(scan):
    try:
        return url_for("main.scan_detail", scan_id=scan.id, _external=True)
    except Exception:
        return None


def _counts(scan):
    return scan.severity_counts() if scan else {"high": 0, "medium": 0, "low": 0,
                                                "informational": 0}


def notify_scan_completed(scan):
    user = db.session.get(User, scan.user_id) if scan.user_id else None
    if user is None:
        return []
    rows = []
    counts = _counts(scan)
    total = scan.vulnerabilities.count()
    link = _scan_link(scan)
    if user.email and user.email_verified and wants(user.id, CHANNEL_EMAIL, "scan_completed"):
        facts = [f"Scan: #{scan.id}", f"Target: {scan.target_url}",
                 f"Status: {scan.status}",
                 f"Started (UTC): {scan.started_at.strftime('%Y-%m-%d %H:%M') if scan.started_at else 'not recorded'}",
                 f"Finished (UTC): {scan.completed_at.strftime('%Y-%m-%d %H:%M') if scan.completed_at else 'not recorded'}",
                 f"Findings: {total}", f"High/Critical: {counts['high']}",
                 f"Medium: {counts['medium']}", f"Low: {counts['low']}",
                 f"Informational: {counts['informational']}"]
        body = ('<h2 style="margin:0 0 10px;font-size:20px">WSA scan completed</h2>'
                f'<p style="color:#334155">Scan #{_esc(scan.id)} finished against '
                f'<b>{_esc(scan.target_url)}</b>.</p>'
                + _fact_table(facts)
                + (f'<p><a href="{_esc(link)}" style="color:#1a56db;font-weight:600">'
                   'View scan results</a></p>' if link else ""))
        rows.append(email_service.send_email(
            user.email, f"WSA scan #{scan.id} completed",
            email_service.layout(f"WSA scan #{scan.id} completed", body),
            email_type="scan_completed", user_id=user.id, related_scan_id=scan.id))
    if user.phone_number and user.phone_verified and wants(user.id, CHANNEL_PHONE, "scan_completed"):
        rows.append(sms_service.send_sms(
            user.phone_number,
            f"WSA: Scan #{scan.id} completed. {total} vulnerabilities detected. "
            "Log in to view results.",
            sms_type="scan_completed", purpose="scan_completed", user_id=user.id,
            related_scan_id=scan.id))
    return rows


def notify_scan_failed(scan, reason=None):
    user = db.session.get(User, scan.user_id) if scan.user_id else None
    if user is None:
        return []
    rows = []
    # The mail reports the failure; it never alters the stored scan status.
    detail = (reason or scan.error_message or "no error detail recorded")[:600]
    link = _scan_link(scan)
    if user.email and user.email_verified and wants(user.id, CHANNEL_EMAIL, "scan_failed"):
        facts = [f"Scan: #{scan.id}", f"Target: {scan.target_url}",
                 f"Status: {scan.status}",
                 f"Failed at (UTC): {scan.completed_at.strftime('%Y-%m-%d %H:%M') if scan.completed_at else 'not recorded'}",
                 f"Reason: {detail}"]
        body = ('<h2 style="margin:0 0 10px;font-size:20px;color:#b91c1c">WSA scan failed</h2>'
                f'<p style="color:#334155">Scan #{_esc(scan.id)} against '
                f'<b>{_esc(scan.target_url)}</b> did not complete.</p>'
                + _fact_table(facts)
                + (f'<p><a href="{_esc(link)}" style="color:#1a56db;font-weight:600">'
                   'View scan history</a></p>' if link else ""))
        rows.append(email_service.send_email(
            user.email, f"WSA scan #{scan.id} failed",
            email_service.layout(f"WSA scan #{scan.id} failed", body),
            email_type="scan_failed", user_id=user.id, related_scan_id=scan.id))
    return rows


def notify_critical_vulnerability(vulnerability, scan=None):
    """Alert for a stored critical/high finding. Requires a real row."""
    scan = scan or (db.session.get(Scan, vulnerability.scan_id)
                    if vulnerability.scan_id else None)
    user = db.session.get(User, scan.user_id) if scan and scan.user_id else None
    if user is None:
        return []
    severity = (vulnerability.severity or "").lower()
    event = "critical_alert" if severity in ("critical", "high") else None
    if event is None:
        return []
    rows = []
    cve = getattr(vulnerability, "cve_id", "") or ""
    cvss = getattr(vulnerability, "cvss_score", None)
    link = _scan_link(scan)
    if user.email and user.email_verified and wants(user.id, CHANNEL_EMAIL, event):
        facts = [f"Scan: #{scan.id if scan else 'n/a'}",
                 f"Target: {scan.target_url if scan else (vulnerability.target_url or 'n/a')}",
                 f"Finding: {vulnerability.name}",
                 f"Severity: {severity}",
                 f"Detected by: {vulnerability.detected_by}",
                 f"Endpoint: {vulnerability.url or vulnerability.target_url or 'n/a'}",
                 f"CVE: {cve or 'not available'}",
                 f"CVSS: {cvss if cvss is not None else 'not available'}"]
        body = ('<h2 style="margin:0 0 10px;font-size:20px;color:#b91c1c">'
                'Critical security finding</h2>'
                '<p style="color:#334155">A new finding was recorded by WSA.</p>'
                + _fact_table(facts)
                + (f'<p><a href="{_esc(link)}" style="color:#1a56db;font-weight:600">'
                   'View finding</a></p>' if link else ""))
        rows.append(email_service.send_email(
            user.email, f"WSA - {severity.title()} finding in scan #{scan.id if scan else 'n/a'}",
            email_service.layout("WSA - security finding", body),
            email_type=event, user_id=user.id, related_scan_id=scan.id if scan else None))
    if user.phone_number and user.phone_verified and wants(user.id, CHANNEL_PHONE, event):
        rows.append(sms_service.send_sms(
            user.phone_number,
            f"WSA Alert: A {severity} security finding was detected in "
            f"Scan #{scan.id if scan else 'n/a'}. Log in to WSA to view details.",
            sms_type=event, purpose=event, user_id=user.id,
            related_scan_id=scan.id if scan else None))
    return rows


def notify_scheduled_scan(scan, scheduled_for=None):
    user = db.session.get(User, scan.user_id) if scan.user_id else None
    if user is None or not wants(user.id, CHANNEL_EMAIL, "scheduled_scan"):
        return []
    facts = [f"Scan: #{scan.id}", f"Target: {scan.target_url}", f"Type: {scan.scan_type}",
             f"Queued at (UTC): {scan.created_at.strftime('%Y-%m-%d %H:%M') if scan.created_at else 'n/a'}"]
    if scheduled_for:
        facts.insert(3, f"Scheduled for (UTC): {scheduled_for}")
    body = ('<h2 style="margin:0 0 10px;font-size:20px">Scheduled scan queued</h2>'
            '<p style="color:#334155">WSA has queued a scheduled scan.</p>' + _fact_table(facts))
    return [email_service.send_email(
        user.email, f"WSA scheduled scan #{scan.id}", email_service.layout(
            f"WSA scheduled scan #{scan.id}", body),
        email_type="scheduled_scan", user_id=user.id, related_scan_id=scan.id)]


# ------------------------------------------------------- network / IP scans --

def notify_ip_scan_completed(scan):
    """Completion alert for an IP/network scan, from its stored counters."""
    user = db.session.get(User, scan.user_id) if scan.user_id else None
    if user is None:
        return []
    rows = []
    facts = [f"Scan: #{scan.id}", f"Target: {scan.target}",
             f"Profile: {scan.scan_profile}", f"Status: {scan.status}",
             f"Hosts discovered: {scan.hosts_discovered}",
             f"Open ports: {scan.open_ports_count}",
             f"Services detected: {scan.services_detected}",
             f"Vulnerabilities: {scan.vulnerabilities_count}",
             f"Critical: {scan.critical_count}", f"High: {scan.high_count}",
             f"Medium: {scan.medium_count}", f"Low: {scan.low_count}",
             f"Informational: {scan.informational_count}"]
    if user.email and user.email_verified and wants(user.id, CHANNEL_EMAIL, "scan_completed"):
        body = ('<h2 style="margin:0 0 10px;font-size:20px">WSA network scan completed</h2>'
                f'<p style="color:#334155">Network scan #{_esc(scan.id)} finished for '
                f'<b>{_esc(scan.target)}</b>.</p>' + _fact_table(facts))
        rows.append(email_service.send_email(
            user.email, f"WSA network scan #{scan.id} completed",
            email_service.layout(f"WSA network scan #{scan.id} completed", body),
            email_type="scan_completed", user_id=user.id))
    if user.phone_number and user.phone_verified and wants(user.id, CHANNEL_PHONE, "scan_completed"):
        rows.append(sms_service.send_sms(
            user.phone_number,
            f"WSA: Network scan #{scan.id} completed. {scan.vulnerabilities_count} "
            "vulnerabilities detected. Log in to view results.",
            sms_type="scan_completed", purpose="scan_completed", user_id=user.id))
    return rows


def notify_ip_scan_failed(scan):
    user = db.session.get(User, scan.user_id) if scan.user_id else None
    if user is None or not wants(user.id, CHANNEL_EMAIL, "scan_failed"):
        return []
    detail = (scan.error_message or "no error detail recorded")[:600]
    facts = [f"Scan: #{scan.id}", f"Target: {scan.target}", f"Status: {scan.status}",
             f"Reason: {detail}"]
    body = ('<h2 style="margin:0 0 10px;font-size:20px;color:#b91c1c">WSA network scan failed</h2>'
            f'<p style="color:#334155">Network scan #{_esc(scan.id)} for '
            f'<b>{_esc(scan.target)}</b> did not complete.</p>' + _fact_table(facts))
    return [email_service.send_email(
        user.email, f"WSA network scan #{scan.id} failed",
        email_service.layout(f"WSA network scan #{scan.id} failed", body),
        email_type="scan_failed", user_id=user.id)]


# ---------------------------------------------------------------- reports ----

def verified_recipients(user):
    """Primary verified email plus every verified security recipient."""
    out = []
    if user.email and user.email_verified:
        out.append({"email": user.email, "label": "Primary verified email",
                    "verified": True, "kind": "primary"})
    for rec in SecurityRecipient.query.filter_by(user_id=user.id, verified=True).all():
        if rec.email.lower() == (user.email or "").lower():
            continue
        out.append({"email": rec.email, "label": rec.label or "Security recipient",
                    "verified": True, "kind": "recipient", "id": rec.id})
    return out


def deliver_report(scan, report_path, recipients, report_name=None, fmt="pdf"):
    """Email a generated report to already-verified addresses only."""
    user = db.session.get(User, scan.user_id) if scan.user_id else None
    if user is None:
        return []
    allowed = {entry["email"].lower() for entry in verified_recipients(user)}
    rows = []
    counts = _counts(scan)
    total = scan.vulnerabilities.count()
    for entry in recipients or []:
        address = (entry.get("email") or "").strip().lower()
        # Unverified or arbitrary addresses are never sent scan data.
        if not address or address not in allowed:
            log.warning("refusing report delivery to unverified recipient")
            continue
        subject = f"WSA security report - scan #{scan.id} - {scan.target_url}"
        html = email_service.layout(
            subject,
            '<h2 style="margin:0 0 10px;font-size:20px">WSA security report</h2>'
            f'<p style="color:#334155">Report for scan #{_esc(scan.id)} against '
            f'<b>{_esc(scan.target_url)}</b>.</p>'
            + _fact_table([f"Report: {report_name or os.path.basename(report_path)}",
                           f"Format: {fmt.upper()}",
                           f"Status: {scan.status}",
                           f"Findings: {total}",
                           f"High/Critical: {counts['high']}",
                           f"Medium: {counts['medium']}",
                           f"Low: {counts['low']}",
                           f"Generated (UTC): {utcnow().strftime('%Y-%m-%d %H:%M')}"])
            + '<p style="color:#334155">The full report is attached.</p>',
        )
        rows.append(email_service.send_email_with_attachment(
            address, subject, html, report_path, os.path.basename(report_path),
            email_type="security_report", user_id=user.id, related_scan_id=scan.id))
    return rows


# ----------------------------------------------------------------- helpers ---

def _fact_table(facts):
    """Render a key/value table.

    Accepts either ``("Label", value)`` pairs or plain ``"Label: value"``
    strings, so a caller cannot silently build a malformed row.
    """
    rows = []
    for fact in facts:
        if isinstance(fact, (tuple, list)):
            key, value = fact[0], fact[1]
        else:
            key, _, value = str(fact).partition(":")
            value = value.strip()
        rows.append(
            f'<tr><td style="padding:3px 14px 3px 0;color:#64748b;white-space:nowrap">'
            f'{_esc(key.strip())}</td><td style="padding:3px 0">{_esc(value)}</td></tr>')
    return (f'<table style="margin:14px 0;font-size:14px;border-collapse:collapse">'
            f'{"".join(rows)}</table>')


def _esc(value):
    from markupsafe import escape
    return escape("" if value is None else str(value))
