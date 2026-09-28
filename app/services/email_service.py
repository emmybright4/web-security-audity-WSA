"""SMTP email delivery with delivery logging.

Every send writes an ``email_logs`` row (sent / failed) with a provider message
id. Credentials live in configuration or the environment and are never returned
to the browser.
"""
import logging
import os
import smtplib
import ssl
from datetime import timezone
from email.headerregistry import Address
from email.message import EmailMessage
from email.utils import format_datetime, make_msgid

from flask import current_app
from markupsafe import escape

from ..extensions import db
from ..models import EmailLog, utcnow

log = logging.getLogger("wsa.email")


class EmailDeliveryError(Exception):
    """Raised when a message could not be handed to the provider."""


def _cfg(key, default=None):
    try:
        return current_app.config.get(key, default)
    except RuntimeError:
        return default


def is_configured():
    return bool((_cfg("MAIL_SERVER", "") or "").strip())


def dev_mailbox():
    """Directory of the development file mailbox, or ``None``.

    ``None`` whenever a real SMTP server is configured or file delivery is off,
    so a page can honestly say *where the code went* during development without
    ever revealing a code itself.
    """
    if is_configured() or not _cfg("MAIL_FILE_DELIVERY", False):
        return None
    return _cfg("MAIL_FILE_DIR") or os.path.join("instance", "mail")


def _sender():
    raw = (_cfg("MAIL_SENDER", "") or "").strip()
    if not raw:
        return None
    if "<" in raw:  # "WSA <no-reply@wsa.local>"
        return raw
    name = _cfg("MAIL_SENDER_NAME", "WSA - Web Security Auditing")
    return str(Address(display_name=name, addr_spec=raw))


def send_email(recipient, subject, html_body, text_body=None, email_type="general",
               user_id=None, related_scan_id=None):
    """Deliver one message. Returns the :class:`EmailLog` row.

    Never raises: transport failures are recorded on the log row so the caller
    can report an accurate status instead of pretending delivery succeeded.
    """
    recipient = (recipient or "").strip()
    log_row = EmailLog(
        user_id=user_id,
        recipient=recipient[:320] or "(missing)",
        email_type=email_type,
        subject=(subject or "")[:255],
        related_scan_id=related_scan_id,
        status="pending",
    )
    db.session.add(log_row)
    try:
        if not recipient or "@" not in recipient:
            raise EmailDeliveryError("Invalid recipient address.")
        message = build_message(recipient, subject, html_body, text_body)
        message_id = _deliver(message)
        log_row.status = "sent"
        log_row.provider_message_id = message_id
        log_row.sent_at = utcnow()
    except Exception as exc:
        db.session.rollback()
        # The rollback may have discarded the pending row; re-add it so the
        # failure itself is auditable.
        log_row = EmailLog(
            user_id=user_id,
            recipient=(recipient[:320] or "(missing)"),
            email_type=email_type,
            subject=(subject or "")[:255],
            related_scan_id=related_scan_id,
            status="failed",
            error_message=str(exc)[:500],
        )
        db.session.add(log_row)
        log.warning("email delivery failed (%s): %s", email_type, exc)
    db.session.commit()
    return log_row


def send_email_with_attachment(recipient, subject, html_body, path, filename,
                              email_type="general", user_id=None, related_scan_id=None):
    """Same contract as :func:`send_email`, with a generated report attached."""
    recipient = (recipient or "").strip()
    log_row = EmailLog(
        user_id=user_id,
        recipient=recipient[:320] or "(missing)",
        email_type=email_type,
        subject=(subject or "")[:255],
        related_scan_id=related_scan_id,
        status="pending",
    )
    db.session.add(log_row)
    try:
        if not recipient or "@" not in recipient:
            raise EmailDeliveryError("Invalid recipient address.")
        if not path or not os.path.exists(path):
            raise EmailDeliveryError("Report file is missing.")
        message = build_message(recipient, subject, html_body, None)
        maintype, subtype = ("application", "pdf") if str(path).lower().endswith(".pdf") \
            else ("text", "html")
        with open(path, "rb") as handle:
            message.add_attachment(handle.read(), maintype=maintype, subtype=subtype,
                                   filename=filename or os.path.basename(path))
        message_id = _deliver(message)
        log_row.status = "sent"
        log_row.provider_message_id = message_id
        log_row.sent_at = utcnow()
    except Exception as exc:
        db.session.rollback()
        log_row = EmailLog(
            user_id=user_id,
            recipient=(recipient[:320] or "(missing)"),
            email_type=email_type,
            subject=(subject or "")[:255],
            related_scan_id=related_scan_id,
            status="failed",
            error_message=str(exc)[:500],
        )
        db.session.add(log_row)
        log.warning("email delivery failed (%s): %s", email_type, exc)
    db.session.commit()
    return log_row


def build_message(recipient, subject, html_body, text_body=None):
    """Multipart message: HTML plus a plain-text alternative."""
    message = EmailMessage()
    message["Subject"] = subject or "WSA notification"
    sender = _sender()
    if sender:
        message["From"] = sender
    message["To"] = recipient
    message["Date"] = format_datetime(datetime_now())
    message["Message-ID"] = make_msgid(domain="wsa.local")
    if text_body is None:
        text_body = strip_html(html_body)
    message.set_content(text_body or "")
    if html_body:
        message.add_alternative(html_body, subtype="html")
    return message


def datetime_now():
    from datetime import datetime
    return datetime.now(timezone.utc)


def _deliver(message):
    server = (_cfg("MAIL_SERVER", "") or "").strip()
    if not server:
        if _cfg("MAIL_FILE_DELIVERY", False):
            return _deliver_to_file(message)
        raise EmailDeliveryError("Email is not configured: set MAIL_SERVER in .env")

    port = int(_cfg("MAIL_PORT", 587) or 587)
    timeout = int(_cfg("MAIL_TIMEOUT_SECONDS", 20) or 20)
    username = (_cfg("MAIL_USERNAME", "") or "").strip()
    password = _cfg("MAIL_PASSWORD", "") or ""
    use_ssl = bool(_cfg("MAIL_USE_SSL", False))
    use_tls = bool(_cfg("MAIL_USE_TLS", True)) and not use_ssl

    if use_ssl:
        client = smtplib.SMTP_SSL(server, port, timeout=timeout,
                                  context=ssl.create_default_context())
    else:
        client = smtplib.SMTP(server, port, timeout=timeout)
    try:
        client.ehlo()
        if use_tls:
            client.starttls(context=ssl.create_default_context())
            client.ehlo()
        if username and password:
            client.login(username, password)
        client.send_message(message)
    finally:
        try:
            client.quit()
        except Exception:  # already disconnected
            pass
    return str(message.get("Message-ID") or "")


def _deliver_to_file(message):
    """Development-only sink: writes .eml files instead of using SMTP."""
    directory = _cfg("MAIL_FILE_DIR") or os.path.join("instance", "mail")
    os.makedirs(directory, exist_ok=True)
    name = f"{utcnow().strftime('%Y%m%d%H%M%S%f')}.eml"
    path = os.path.join(directory, name)
    with open(path, "w", encoding="utf-8") as handle:
        handle.write(str(message))
    # Say where the message went: with file delivery on, the "inbox" is a file.
    log.info("development mail written to %s (MAIL_FILE_DELIVERY is on)", path)
    return path


# ------------------------------------------------------------------ HTML ----

def layout(title, body_html, preheader=""):
    """Shared, escaped-by-default HTML shell for WSA messages."""
    return (
        "<!doctype html><html><body style=\"margin:0;padding:0;background:#f1f5f9;"
        "font-family:Segoe UI,Roboto,Helvetica,Arial,sans-serif;color:#0f172a\">"
        f"<span style=\"display:none;max-height:0;overflow:hidden\">{escape(preheader)}</span>"
        "<table role=\"presentation\" width=\"100%\" cellpadding=\"0\" cellspacing=\"0\">"
        "<tr><td align=\"center\" style=\"padding:24px 12px\">"
        "<table role=\"presentation\" width=\"600\" cellpadding=\"0\" cellspacing=\"0\" "
        "style=\"max-width:600px;background:#ffffff;border-radius:14px;overflow:hidden;"
        "border:1px solid #e2e8f0\">"
        "<tr><td style=\"background:#1a56db;padding:18px 24px;color:#fff\">"
        "<div style=\"font-size:18px;font-weight:800;letter-spacing:.5px\">"
        "WSA &mdash; Web Security Auditing</div></td></tr>"
        f"<tr><td style=\"padding:26px 24px\">{body_html}</td></tr>"
        "<tr><td style=\"padding:16px 24px;background:#f8fafc;color:#64748b;font-size:12px\">"
        "WSA &mdash; Web Security Auditing. You received this message because you are "
        "registered on this WSA instance.</td></tr>"
        "</table></td></tr></table></body></html>"
    )


def code_block(code):
    """Render an OTP for display. Only ever called with a live code."""
    digits = "".join(ch for ch in str(code) if ch.isdigit())
    cells = "".join(
        f'<span style="display:inline-block;min-width:38px;padding:10px 0;margin:0 3px;'
        f'text-align:center;font-size:22px;font-weight:800;background:#eef2ff;'
        f'color:#1e3a8a;border-radius:8px">{d}</span>' for d in digits)
    return (f'<div style="text-align:center;margin:18px 0">{cells}</div>')


def strip_html(html):
    """Crude but dependency-free plain-text fallback for a notification."""
    if not html:
        return ""
    import re
    text = re.sub(r"(?is)<(script|style).*?>.*?</\1>", " ", html)
    text = re.sub(r"(?i)<br\s*/?>", "\n", text)
    text = re.sub(r"(?i)</(p|div|tr|h[1-6]|li)>", "\n", text)
    text = re.sub(r"<[^>]+>", " ", text)
    text = (text.replace("&nbsp;", " ").replace("&amp;", "&")
                .replace("&lt;", "<").replace("&gt;", ">").replace("&mdash;", "-"))
    return re.sub(r"\n{3,}", "\n\n", re.sub(r"[ \t]{2,}", " ", text)).strip()
