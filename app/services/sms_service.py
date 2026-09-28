"""SMS delivery behind a provider registry.

The provider is chosen entirely by configuration (``SMS_PROVIDER`` +
credentials), so swapping gateways never touches the auth or notification
code. Credentials stay server-side; nothing here is ever exposed to the client.

Implemented providers:
  * ``africas_talking``  - https://api.africastalking.com/version1/messaging
  * ``twilio``           - https://api.twilio.com/2010-04-01/Accounts/.../Messages.json
  * ``http``             - any JSON gateway described by SMS_API_URL
  * ``file``             - development sink (SMS_ALLOW_FILE_PROVIDER must be on)
"""
import json
import logging
import os

from flask import current_app

from ..extensions import db
from ..models import SmsLog, utcnow
from .phone_service import normalize, PhoneError

log = logging.getLogger("wsa.sms")

_REGISTRY = {}


class SMSDeliveryError(Exception):
    """Raised when a gateway rejected or could not accept a message."""


class SMSProvider:
    name = "base"

    def __init__(self, config):
        self.config = config

    def send(self, to, body):  # pragma: no cover - interface
        raise NotImplementedError


def _cfg(key, default=None):
    try:
        return current_app.config.get(key, default)
    except RuntimeError:
        return default


def register(cls):
    _REGISTRY[cls.name] = cls
    return cls


def get_provider():
    """Instantiate the configured provider, or None when unusable."""
    name = (_cfg("SMS_PROVIDER", "") or "").strip().lower()
    if not name:
        return None
    if name in ("file", "console", "dev"):
        if not _cfg("SMS_ALLOW_FILE_PROVIDER", False):
            log.warning("SMS provider '%s' is development-only and is disabled.", name)
            return None
        return FileSMSProvider(_cfg)
    cls = _REGISTRY.get(name)
    if cls is None:
        log.warning("Unknown SMS_PROVIDER '%s'; no provider will run.", name)
        return None
    return cls(_cfg)


def provider_status():
    provider = get_provider()
    return {
        "configured": provider is not None,
        "provider": (_cfg("SMS_PROVIDER", "") or "").strip().lower() or None,
        "sender_id_set": bool((_cfg("SMS_SENDER_ID", "") or "").strip()),
        "api_key_set": bool((_cfg("SMS_API_KEY", "") or "").strip()),
        "development_sink": provider is not None and isinstance(provider, FileSMSProvider),
    }


def send_sms(to, body, sms_type="general", purpose="", user_id=None, related_scan_id=None):
    """Deliver one SMS. Returns the :class:`SmsLog` row; never raises."""
    try:
        to = normalize(to)
    except PhoneError as exc:
        return _record(to, body, sms_type, purpose, user_id, related_scan_id,
                       status="failed", error=str(exc))
    if len(str(body or "")) > 480:
        body = str(body)[:477] + "..."

    provider = get_provider()
    if provider is None:
        return _record(to, body, sms_type, purpose, user_id, related_scan_id,
                       status="failed",
                       error="SMS provider is not configured: set SMS_PROVIDER in .env")
    try:
        message_id = provider.send(to, body)
        return _record(to, body, sms_type, purpose, user_id, related_scan_id,
                       status="sent", provider_message_id=str(message_id or ""))
    except Exception as exc:
        log.warning("SMS delivery failed (%s): %s", sms_type, exc)
        return _record(to, body, sms_type, purpose, user_id, related_scan_id,
                       status="failed", error=str(exc)[:500])


def _record(to, body, sms_type, purpose, user_id, scan_id, status,
            provider_message_id="", error=""):
    row = SmsLog(
        user_id=user_id,
        phone_number=(str(to) or "(unknown)")[:20],
        sms_type=sms_type,
        purpose=(purpose or "")[:32],
        related_scan_id=scan_id,
        status=status,
        provider_message_id=(provider_message_id or "")[:255],
        error_message=(error or "")[:500],
        sent_at=utcnow() if status == "sent" else None,
    )
    db.session.add(row)
    try:
        db.session.commit()
    except Exception:
        db.session.rollback()
    return row


# ------------------------------------------------------------- providers ----

def _requests():
    import requests
    return requests


@register
class AfricasTalkingSMS(SMSProvider):
    name = "africas_talking"

    ENDPOINT = "https://api.africastalking.com/version1/messaging"

    def send(self, to, body):
        username = (self.config("SMS_API_KEY", "") or "").strip()
        password = (self.config("SMS_API_SECRET", "") or "").strip()
        if not username:
            raise SMSDeliveryError("SMS_API_KEY (account username) is not set.")
        from base64 import b64encode
        auth = b64encode(f"{username}:{password}".encode()).decode()
        response = _requests().post(
            self.config("SMS_API_URL", "") or self.ENDPOINT,
            data={"to": to, "message": body,
                  "from": (self.config("SMS_SENDER_ID", "") or "WSA").strip()},
            headers={"Authorization": f"Basic {auth}"},
            timeout=int(self.config("SMS_TIMEOUT_SECONDS", 20) or 20),
        )
        if response.status_code >= 400:
            raise SMSDeliveryError(f"HTTP {response.status_code}")
        payload = _json(response)
        recipients = payload.get("SMSMessageData", {}).get("Recipients") or []
        if recipients and str(recipients[0].get("StatusCode", "0")) != "0":
            raise SMSDeliveryError(f"gateway status {recipients[0].get('StatusCode')}")
        return (recipients[0].get("MessageID") if recipients else "") or "ok"


@register
class TwilioSMS(SMSProvider):
    name = "twilio"

    def send(self, to, body):
        sid = (self.config("SMS_API_KEY", "") or "").strip()
        token = (self.config("SMS_API_SECRET", "") or "").strip()
        if not sid or not token:
            raise SMSDeliveryError("SMS_API_KEY / SMS_API_SECRET are not set.")
        from base64 import b64encode
        url = (self.config("SMS_API_URL", "") or "").strip()
        if not url:
            raise SMSDeliveryError("Set SMS_API_URL to the Twilio account messages endpoint.")
        auth = b64encode(f"{sid}:{token}".encode()).decode()
        response = _requests().post(
            url,
            data={"To": to, "From": (self.config("SMS_SENDER_ID", "") or "").strip(),
                  "Body": body},
            headers={"Authorization": f"Basic {auth}"},
            timeout=int(self.config("SMS_TIMEOUT_SECONDS", 20) or 20),
        )
        if response.status_code >= 400:
            raise SMSDeliveryError(f"HTTP {response.status_code}")
        return _json(response).get("sid", "")


@register
class GenericHttpSMS(SMSProvider):
    """POST JSON ``{to, message, from}`` to any compatible gateway."""

    name = "http"

    def send(self, to, body):
        url = (self.config("SMS_API_URL", "") or "").strip()
        if not url:
            raise SMSDeliveryError("SMS_API_URL is required for the http provider.")
        key = (self.config("SMS_API_KEY", "") or "").strip()
        headers = {"Content-Type": "application/json"}
        if key:
            headers["Authorization"] = f"Bearer {key}"
        response = _requests().post(
            url,
            data=json.dumps({"to": to, "message": body,
                             "from": (self.config("SMS_SENDER_ID", "") or "WSA").strip()}),
            headers=headers,
            timeout=int(self.config("SMS_TIMEOUT_SECONDS", 20) or 20),
        )
        if response.status_code >= 400:
            raise SMSDeliveryError(f"HTTP {response.status_code}")
        return _json(response).get("id", "") or _json(response).get("messageId", "ok")


class FileSMSProvider(SMSProvider):
    """Development sink: appends messages to a local file. Not for production."""

    name = "file"

    def send(self, to, body):
        directory = self.config("SMS_FILE_DIR") or os.path.join("instance", "sms")
        os.makedirs(directory, exist_ok=True)
        path = os.path.join(directory, "outbox.log")
        with open(path, "a", encoding="utf-8") as handle:
            handle.write(json.dumps({"at": utcnow().isoformat(), "to": to,
                                     "message": body}) + "\n")
        log.warning("SMS written to development sink %s (not delivered)", path)
        return path


def _json(response):
    try:
        return response.json()
    except Exception:
        return {}
