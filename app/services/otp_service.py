"""Backend-only six-digit OTP lifecycle.

Rules enforced here (never in the browser):
  * cryptographically secure generation (``secrets``)
  * stored as a salted hash only
  * one-time use
  * expiry
  * attempt limit
  * resend cooldown
  * issuing a new code invalidates the previous active one
"""
import logging
import secrets
from datetime import datetime, timedelta, timezone

from flask import current_app
from werkzeug.security import check_password_hash, generate_password_hash

from ..extensions import db
from ..models import (CHANNEL_EMAIL, CHANNEL_PHONE, VerificationCode,
                      _aware, utcnow)

log = logging.getLogger("wsa.otp")


class OTPError(Exception):
    """Raised with a user-safe message; never carries backend internals."""


def _cfg(key, default):
    try:
        return current_app.config.get(key, default)
    except RuntimeError:  # outside an app context (CLI / tests)
        return default


def generate_code():
    """A cryptographically secure numeric code of OTP_LENGTH digits."""
    length = max(4, min(10, int(_cfg("OTP_LENGTH", 6))))
    return "".join(str(secrets.randbelow(10)) for _ in range(length))


def hash_code(code):
    # PBKDF2/scrypt keeps a 6-digit code from being recovered by a rainbow
    # table if verification_codes is ever exfiltrated.
    return generate_password_hash(str(code))


def matches(code, code_hash):
    if not code or not code_hash:
        return False
    try:
        return check_password_hash(code_hash, str(code))
    except (ValueError, TypeError):
        return False


def is_well_formed(code, channel=CHANNEL_EMAIL):
    code = str(code or "").strip().replace(" ", "")
    length = int(_cfg("OTP_LENGTH", 6))
    if not code.isdigit() or len(code) != length:
        return False
    return True


def expiration_minutes():
    return max(1, int(_cfg("OTP_EXPIRATION_MINUTES", 10)))


def code_length():
    return max(4, min(10, int(_cfg("OTP_LENGTH", 6))))


def max_attempts():
    return max(1, int(_cfg("OTP_MAX_ATTEMPTS", 5)))


def resend_cooldown_seconds():
    return max(0, int(_cfg("OTP_RESEND_COOLDOWN_SECONDS", 60)))


# --------------------------------------------------------------- issuing ----

def _invalidate_previous(query, now):
    """Only the newest active code may ever be accepted."""
    stale = [c for c in query.all() if c.is_active(now)]
    for code_row in stale:
        code_row.invalidated_at = now
    return len(stale)


def create_challenge(user_id, channel, purpose, destination, recipient_id=None,
                     commit=True):
    """Create and persist a fresh challenge.

    Returns ``(record, plaintext_code)``. The plaintext is handed straight to
    the email/SMS service and is never logged or stored.
    """
    if channel not in (CHANNEL_EMAIL, CHANNEL_PHONE):
        raise OTPError("Unsupported verification channel.")
    if not destination:
        raise OTPError("A destination is required to send a verification code.")

    now = utcnow()
    query = VerificationCode.query.filter_by(user_id=user_id, purpose=purpose, channel=channel)
    _invalidate_previous(query, now)

    code = generate_code()
    record = VerificationCode(
        user_id=user_id,
        recipient_id=recipient_id,
        channel=channel,
        purpose=purpose,
        destination=destination,
        code_hash=hash_code(code),
        expires_at=now + timedelta(minutes=expiration_minutes()),
        attempt_count=0,
        max_attempts=max_attempts(),
        used=False,
        created_at=now,
    )
    db.session.add(record)
    if commit:
        db.session.commit()
    return record, code


def cooldown_left(user_id, purpose, channel, recipient_id=None):
    """Seconds until another code may be issued for this target."""
    cooldown = resend_cooldown_seconds()
    if cooldown <= 0:
        return 0
    now = utcnow()
    query = VerificationCode.query.filter_by(purpose=purpose, channel=channel)
    if recipient_id is not None:
        query = query.filter_by(recipient_id=recipient_id)
    else:
        query = query.filter_by(user_id=user_id)
    last = query.order_by(VerificationCode.created_at.desc()).first()
    if last is None:
        return 0
    elapsed = (now - _aware(last.created_at)).total_seconds()
    return max(0, int(cooldown - elapsed))


def active_challenge(user_id, purpose, channel=None, recipient_id=None):
    """The one live code for this target, or None."""
    query = VerificationCode.query.filter_by(user_id=user_id, purpose=purpose)
    if channel:
        query = query.filter_by(channel=channel)
    if recipient_id is not None:
        query = query.filter_by(recipient_id=recipient_id)
    now = utcnow()
    candidates = [c for c in query.order_by(VerificationCode.created_at.desc()).limit(5).all()
                  if c.is_active(now)]
    return candidates[0] if candidates else None


# ------------------------------------------------------------- validating ----

def verify(record, code):
    """Validate ``code`` against ``record``.

    Returns ``(ok, message)`` with a user-safe message. Consumes an attempt on
    every call, including expired and already-used rows, so an attacker cannot
    probe states for free.
    """
    now = utcnow()

    if record is None:
        return False, "No active verification code. Request a new one."
    if record.used or record.invalidated_at:
        return False, "This verification code is no longer valid. Request a new one."
    if record.is_expired(now):
        return False, "OTP expired. Request a new code."

    if not is_well_formed(code, record.channel):
        return _fail(record, "Enter the 6-digit verification code.")

    record.attempt_count = int(record.attempt_count or 0) + 1
    if not matches(str(code).strip(), record.code_hash):
        left = record.attempts_left()
        if left <= 0:
            record.invalidated_at = now
            db.session.commit()
            return False, ("Too many incorrect attempts. This verification code has been "
                           "locked. Request a new code.")
        db.session.commit()
        return False, f"Invalid verification code. {left} attempt{'s' if left != 1 else ''} remaining."

    record.used = True
    record.used_at = now
    db.session.commit()
    return True, "Verification successful."


def _fail(record, message):
    record.attempt_count = int(record.attempt_count or 0) + 1
    if record.attempts_left() <= 0:
        record.invalidated_at = utcnow()
        db.session.commit()
        return False, ("Too many incorrect attempts. This verification code has been "
                       "locked. Request a new code.")
    db.session.commit()
    return False, message


def status_for(record, now=None):
    """(state, seconds_remaining) for the verification UI countdown."""
    now = now or utcnow()
    if record is None:
        return "missing", 0
    if record.used:
        return "used", 0
    if record.invalidated_at:
        return "invalidated", 0
    remaining = int((_aware(record.expires_at) - now).total_seconds())
    if remaining <= 0:
        return "expired", 0
    return "active", remaining
