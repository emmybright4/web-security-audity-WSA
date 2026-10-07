"""Settings API: platform settings, notification preferences and delivery logs."""
import re

from flask import Blueprint, current_app, jsonify, request
from sqlalchemy import desc

from ..extensions import db
from ..models import (EmailLog, PURPOSE_RECIPIENT_VERIFICATION, SecurityRecipient,
                      Setting, SmsLog, utcnow, VerificationCode)
from ..services import notification_service, otp_service, rate_limit
from ..services.engines import zap_mcp, zap_service
from ._api_guard import api_login_required
from .auth import DeliveryFailed, _masked, _send, current_row

bp = Blueprint("settings", __name__, url_prefix="/api/settings")

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")

ALLOWED_KEYS = {"default_scan_type", "polling_fallback_seconds", "max_pages",
                "notifications_enabled", "confirm_authorization", "theme",
                "zap_api_url", "zap_api_key", "zap_mcp_url",
                "ai_provider", "ai_api_key", "ai_model", "ai_base_url"}

AI_PROVIDERS = ("openai", "anthropic", "custom")

# Keys whose raw values must never be echoed back to the client.
SENSITIVE_KEYS = {"zap_api_key", "ai_api_key"}

# DB setting key -> app.config key. DB values win over .env at runtime.
CONFIG_OVERRIDES = {"zap_api_url": "ZAP_API_URL", "zap_api_key": "ZAP_API_KEY",
                    "zap_mcp_url": "ZAP_MCP_URL",
                    "ai_provider": "AI_PROVIDER", "ai_api_key": "AI_API_KEY",
                    "ai_model": "AI_MODEL", "ai_base_url": "AI_BASE_URL"}

# Keys where an empty stored value is an explicit "off" and therefore clears the
# .env value, instead of meaning "nothing saved here, keep .env". Clearing
# ai_provider is how the AI card is switched off again; ai_api_key is deliberately
# absent, because an empty secret keeps the stored one (see SENSITIVE_KEYS).
CLEARABLE_KEYS = {"zap_mcp_url", "ai_provider", "ai_model", "ai_base_url"}


def apply_db_settings(app):
    """Overlay DB-stored engine settings on app.config (DB wins over .env)."""
    for key, cfg_key in CONFIG_OVERRIDES.items():
        row = Setting.query.filter_by(key=key).first()
        if row is None:
            continue
        value = str(row.value or "").strip()
        if not value and key not in CLEARABLE_KEYS:
            continue
        app.config[cfg_key] = value


def _db_value(key):
    row = Setting.query.filter_by(key=key).first()
    return str((row.value if row else None) or "")


def _mask(secret):
    if not secret:
        return ""
    return "••••••••" + secret[-4:] if len(secret) > 8 else "••••••••"


@bp.get("")
@api_login_required
def get_settings():
    rows = Setting.query.all()
    values = {r.key: r.value for r in rows}
    values.pop("zap_api_key", None)  # never leak the raw key to the client
    values.pop("ai_api_key", None)   # ...same for the provider key

    effective_key = _db_value("zap_api_key") or current_app.config.get("ZAP_API_KEY", "")
    values["zap_api_key_set"] = bool(effective_key)
    values["zap_api_key_masked"] = _mask(effective_key)
    if not _db_value("zap_api_url").strip():
        values["zap_api_url"] = current_app.config.get("ZAP_API_URL", "")
    # An empty MCP URL is an explicit "native ZAP API mode", so only fall back to
    # .env when the key has never been saved at all.
    values.setdefault("zap_mcp_url", current_app.config.get("ZAP_MCP_URL", ""))
    # AI: the key is reported as present/absent only, and the plain settings fall
    # back to .env while an explicitly saved empty value stays empty.
    effective_ai_key = _db_value("ai_api_key") or current_app.config.get("AI_API_KEY", "")
    values["ai_api_key_set"] = bool(effective_ai_key)
    values["ai_api_key_masked"] = _mask(effective_ai_key)
    for cfg_key, db_key in (("AI_PROVIDER", "ai_provider"),
                            ("AI_MODEL", "ai_model"),
                            ("AI_BASE_URL", "ai_base_url")):
        values.setdefault(db_key, current_app.config.get(cfg_key, ""))
    values.setdefault("default_scan_type", "quick")
    values.setdefault("polling_fallback_seconds",
                      current_app.config.get("POLLING_FALLBACK_SECONDS", 4))
    values.setdefault("max_pages", 12)
    values.setdefault("notifications_enabled", True)
    values.setdefault("confirm_authorization", True)
    return jsonify(settings=values)


@bp.put("")
@api_login_required
def put_settings():
    data = request.get_json(silent=True) or {}
    updated = {}
    for key, value in data.items():
        if key not in ALLOWED_KEYS:
            continue
        value = str(value).strip() if isinstance(value, str) else value
        if key == "zap_api_url" and isinstance(value, str):
            value = value.rstrip("/")
        if key == "ai_provider" and isinstance(value, str):
            value = value.lower()
        if key in SENSITIVE_KEYS and not str(value or "").strip():
            continue  # empty secret = keep the stored value
        row = db.session.get(Setting, key)
        if row is None:
            row = Setting(key=key)
            db.session.add(row)
        row.value = value
        # The GET handler strips secrets; the save response must not reintroduce
        # them, or the raw key would travel back on every Settings save.
        updated[key] = _mask(value) if key in SENSITIVE_KEYS else value
    try:
        db.session.commit()
    except Exception as exc:
        db.session.rollback()
        return jsonify(error=f"Could not save settings: {exc}"), 500
    apply_db_settings(current_app)  # engine settings take effect immediately, no restart
    return jsonify(message=f"Saved {len(updated)} setting(s).", settings=updated)


@bp.post("/zap/test")
@api_login_required
def test_zap():
    """Ping ZAP with the submitted values, or the saved/configured ones if omitted."""
    data = request.get_json(silent=True) or {}
    url = str(data.get("zap_api_url") or "").strip().rstrip("/")
    key = str(data.get("zap_api_key") or "").strip()
    if not url:
        url = _db_value("zap_api_url") or current_app.config.get("ZAP_API_URL", "")
    if not key:
        key = _db_value("zap_api_key") or current_app.config.get("ZAP_API_KEY", "")
    if not url:
        return jsonify(ok=False, version="", detail="No ZAP API URL provided or saved.")
    ok, version, detail = zap_service.ping({"ZAP_API_URL": url, "ZAP_API_KEY": key})
    return jsonify(ok=ok, version=version, detail=detail)


@bp.post("/zap-mcp/test")
@api_login_required
def test_zap_mcp():
    """Probe the MCP endpoint with the submitted value, or the saved/configured one."""
    data = request.get_json(silent=True) or {}
    url = str(data.get("zap_mcp_url") or "").strip().rstrip("/")
    if not url:
        url = _db_value("zap_mcp_url") or current_app.config.get("ZAP_MCP_URL", "")
    ok, detail = zap_mcp.availability({"ZAP_MCP_URL": url,
                                       "ZAP_API_URL": current_app.config.get("ZAP_API_URL", ""),
                                       "ZAP_API_KEY": current_app.config.get("ZAP_API_KEY", "")})
    return jsonify(ok=ok, detail=detail)


@bp.post("/ai/test")
@api_login_required
def test_ai():
    """Validate the submitted AI settings, falling back to the saved/configured ones."""
    from ..services.engines import ai_service

    data = request.get_json(silent=True) or {}

    def pick(field, cfg_key):
        value = str(data.get(field) or "").strip()
        if value:
            return value
        return _db_value(field) or str(current_app.config.get(cfg_key, "") or "")

    provider = pick("ai_provider", "AI_PROVIDER").lower()
    config = {"AI_PROVIDER": provider,
              "AI_API_KEY": pick("ai_api_key", "AI_API_KEY"),
              "AI_MODEL": pick("ai_model", "AI_MODEL"),
              "AI_BASE_URL": pick("ai_base_url", "AI_BASE_URL")}
    if provider and provider not in AI_PROVIDERS:
        return jsonify(ok=False,
                       detail=f"Unknown provider '{provider}'. Use one of: "
                              f"{', '.join(AI_PROVIDERS)}.")
    # availability() first (no network) so a half-filled form fails fast and
    # cheaply; ping() then sends the real request.
    ok, detail = ai_service.availability(config)
    if not ok:
        return jsonify(ok=False, detail=detail)
    ok, detail = ai_service.ping(config)
    return jsonify(ok=ok, detail=detail)


# =====================================================================
# Notification preferences
# =====================================================================

@bp.get("/notifications")
@api_login_required
def get_notifications():
    user = current_row()
    prefs = notification_service.preferences_for(user.id)
    return jsonify(
        preferences=prefs,
        email_events=[{"key": key, "label": label, "default": default}
                      for key, (default, label) in notification_service.EMAIL_EVENTS.items()],
        sms_events=[{"key": key, "label": label, "default": default}
                    for key, (default, label) in notification_service.SMS_EVENTS.items()],
        channels=[{"channel": c, "destination": _masked(c, d)}
                  for c, d in user.verified_channels()],
        email_configured=bool(current_app.config.get("MAIL_SERVER", "").strip()),
        sms=sms_service.provider_status(),
        verification={
            "expires_minutes": otp_service.expiration_minutes(),
            "max_attempts": otp_service.max_attempts(),
            "resend_cooldown_seconds": otp_service.resend_cooldown_seconds(),
        },
    )


@bp.put("/notifications")
@api_login_required
def put_notifications():
    data = request.get_json(silent=True) or {}
    row = notification_service.set_preferences(
        current_row().id, data.get("email") or {}, data.get("sms") or {})
    return jsonify(message="Notification preferences saved.", preferences=row.to_dict())


# =====================================================================
# Delivery history (real rows only)
# =====================================================================

@bp.get("/notifications/email-history")
@api_login_required
def email_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    rows = (EmailLog.query.filter_by(user_id=current_row().id)
            .order_by(desc(EmailLog.created_at)).limit(limit).all())
    return jsonify(emails=[r.to_dict() for r in rows])


@bp.get("/notifications/sms-history")
@api_login_required
def sms_history():
    limit = min(int(request.args.get("limit", 100)), 500)
    rows = (SmsLog.query.filter_by(user_id=current_row().id)
            .order_by(desc(SmsLog.created_at)).limit(limit).all())
    return jsonify(messages=[r.to_dict() for r in rows])


# =====================================================================
# Authorised security recipients
# =====================================================================

@bp.get("/recipients")
@api_login_required
def list_recipients():
    user = current_row()
    rows = (SecurityRecipient.query.filter_by(user_id=user.id)
            .order_by(desc(SecurityRecipient.created_at)).all())
    return jsonify(recipients=[r.to_dict() for r in rows],
                   primary=_primary_recipient(user),
                   email_configured=bool(current_app.config.get("MAIL_SERVER", "").strip()))


def _primary_recipient(user):
    if not (user.email and user.email_verified):
        return None
    return {"email": user.email, "label": "Primary verified email", "verified": True,
            "kind": "primary"}


@bp.post("/recipients")
@api_login_required
def add_recipient():
    data = request.get_json(silent=True) or {}
    address = str(data.get("email") or "").strip().lower()
    label = str(data.get("label") or "").strip()[:80] or "Security Team"
    user = current_row()

    if not EMAIL_RE.match(address):
        return jsonify(error="Enter a valid email address."), 400
    if user.email and address == user.email.lower():
        return jsonify(error="That is already your primary verified email."), 400
    existing = SecurityRecipient.query.filter_by(user_id=user.id, email=address).first()
    if existing is not None:
        return jsonify(error="That recipient is already on your list."), 409

    allowed, retry = rate_limit.check("recipient_add", f"{user.id}", 5, 3600)
    if not allowed:
        return jsonify(error=f"Too many recipient requests. Try again in {retry} seconds."), 429

    record = SecurityRecipient(user_id=user.id, email=address, label=label, verified=False)
    db.session.add(record)
    db.session.commit()
    # The address only becomes deliverable after it proves control of the inbox.
    try:
        _send(user, "email", PURPOSE_RECIPIENT_VERIFICATION, recipient_id=record.id)
    except DeliveryFailed as exc:
        db.session.delete(record)
        db.session.commit()
        return jsonify(error=str(exc)), 503
    return jsonify(message=f"A verification code was sent to {address}.",
                   recipient=record.to_dict()), 201


@bp.post("/recipients/<int:recipient_id>/resend")
@api_login_required
def resend_recipient(recipient_id):
    user = current_row()
    record = SecurityRecipient.query.filter_by(id=recipient_id, user_id=user.id).first()
    if record is None:
        return jsonify(error="Recipient not found."), 404

    cooldown = otp_service.cooldown_left(user.id, PURPOSE_RECIPIENT_VERIFICATION, "email",
                                         recipient_id=record.id)
    if cooldown > 0:
        return jsonify(error=f"Please wait {cooldown} seconds before requesting another code.",
                       resend_in=cooldown), 429
    try:
        challenge = _send(user, "email", PURPOSE_RECIPIENT_VERIFICATION, recipient_id=record.id)
    except DeliveryFailed as exc:
        return jsonify(error=str(exc)), 503
    return jsonify(message=f"A new code was sent to {record.email}.",
                   expires_in=otp_service.status_for(challenge)[1],
                   resend_in=otp_service.resend_cooldown_seconds())


@bp.post("/recipients/<int:recipient_id>/verify")
@api_login_required
def verify_recipient(recipient_id):
    data = request.get_json(silent=True) or {}
    code = str(data.get("code") or "").strip()
    user = current_row()
    record = SecurityRecipient.query.filter_by(id=recipient_id, user_id=user.id).first()
    if record is None:
        return jsonify(error="Recipient not found."), 404

    allowed, _retry = rate_limit.check("recipient_verify", f"{user.id}:{record.id}", 10, 600)
    if not allowed:
        return jsonify(error="Too many attempts. Try again later."), 429

    challenge = otp_service.active_challenge(user.id, PURPOSE_RECIPIENT_VERIFICATION,
                                             channel="email", recipient_id=record.id)
    ok, message = otp_service.verify(challenge, code)
    if not ok:
        return jsonify(error=message), 400
    record.verified = True
    record.verified_at = utcnow()
    db.session.commit()
    return jsonify(message=f"{record.email} is now a verified recipient.",
                   recipient=record.to_dict())


@bp.delete("/recipients/<int:recipient_id>")
@api_login_required
def delete_recipient(recipient_id):
    user = current_row()
    record = SecurityRecipient.query.filter_by(id=recipient_id, user_id=user.id).first()
    if record is None:
        return jsonify(error="Recipient not found."), 404
    VerificationCode.query.filter_by(recipient_id=record.id).delete(synchronize_session=False)
    db.session.delete(record)
    db.session.commit()
    return jsonify(message="Recipient removed.")
