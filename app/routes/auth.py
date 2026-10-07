"""Authentication: email/phone sign-up, OTP verification, login, password reset.

Security model
--------------
* All OTPs are generated, hashed, expired, rate-limited and validated here. The
  browser never sees a code before it is delivered by email or SMS.
* The subject of a verification challenge is taken from the *server-side
  session* (a signed cookie) that registration, login-MFA or password reset
  created. A browser-supplied user id is never trusted.
* Password reset answers identically whether or not the account exists.
"""
import logging
import re

from flask import (Blueprint, jsonify, redirect, render_template, request,
                   session, url_for)
from flask_login import (UserMixin, current_user, login_user, logout_user,
                         login_required)

from sqlalchemy.exc import IntegrityError

from ..extensions import db, login_manager
from ..models import (CHANNEL_EMAIL, CHANNEL_PHONE, PURPOSE_ACCOUNT_VERIFICATION,
                      PURPOSE_LOGIN_VERIFICATION, PURPOSE_PASSWORD_RESET,
                      User, VerificationCode)
from ..services import (email_service, notification_service, otp_service,
                       rate_limit, sms_service)
from ..services.phone_service import (PhoneError, country_options, default_country,
                                      mask_phone, normalize)
from ._api_guard import api_login_required

log = logging.getLogger("wsa.auth")

bp = Blueprint("auth", __name__)

EMAIL_RE = re.compile(r"^[^@\s]+@[^@\s]+\.[^@\s]{2,}$")
PHONE_HINT = re.compile(r"[+0-9]")

# Session key holding the challenge the browser is currently working on.
PENDING_KEY = "pending_verification"
RESET_OK_KEY = "password_reset_granted"
# MFA is issued before the session cookie is promoted to a real login.
LOGIN_PENDING_KEY = "pending_login_identity"
# Marks "a reset was requested" without saying whether an account exists.
RESET_REQUESTED_KEY = "reset_requested"

VALID_CHANNELS = {CHANNEL_EMAIL, CHANNEL_PHONE}

# Who is signing up. Picking a role keeps the workspace honest about who is
# auditing what; "Other" lets a visitor describe themselves in a few words.
ROLE_OPTIONS = [
    "SOC Analyst",
    "Penetration Tester",
    "Security Engineer",
    "System Administrator",
    "Developer",
    "IT Student",
]
ROLE_OTHER = "Other"


class LoginUser(UserMixin):
    """Adapter exposing the SQLAlchemy User to Flask-Login."""

    def __init__(self, row):
        self.row = row

    def get_id(self):
        return str(self.row.id)


@login_manager.user_loader
def load_user(user_id):
    row = db.session.get(User, int(user_id))
    return LoginUser(row) if row else None


def current_row():
    return getattr(current_user, "row", None)


# ----------------------------------------------------------------- helpers ----

def _client_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()[:64]
    return (request.remote_addr or "unknown")[:64]


def _password_problem(password):
    if not password or len(password) < 8:
        return "Password must be at least 8 characters."
    if not (any(c.isalpha() for c in password) and any(c.isdigit() for c in password)):
        return "Password must contain at least one letter and one number."
    return None


def _masked(channel, destination):
    if channel == CHANNEL_PHONE:
        return mask_phone(destination)
    local, _, domain = (destination or "").partition("@")
    head = local[:1] if local else "u"
    return f"{head}***@{domain}" if domain else "***"


def _set_pending(user, channel, purpose, challenge_id, destination, *,
                 allow_mfa=False, allow_reset=False):
    """Remember which challenge this browser session may answer."""
    session[PENDING_KEY] = {
        "user_id": user.id,
        "channel": channel,
        "purpose": purpose,
        "challenge_id": challenge_id,
        "destination": destination,
        "allow_mfa": bool(allow_mfa),
        "allow_reset": bool(allow_reset),
    }
    session[RESET_OK_KEY] = bool(allow_reset)


def _clear_pending():
    session.pop(PENDING_KEY, None)
    session.pop(RESET_OK_KEY, None)
    session.pop(LOGIN_PENDING_KEY, None)
    session.pop(RESET_REQUESTED_KEY, None)


def _pending():
    data = session.get(PENDING_KEY)
    if not data or not data.get("user_id"):
        return None
    return data


def _pending_challenge():
    data = _pending()
    if not data:
        return None
    return db.session.get(VerificationCode, data["challenge_id"])


def _challenge_payload(record, purpose=None, message=None):
    state, remaining = otp_service.status_for(record)
    payload = {
        "channel": record.channel if record else None,
        "purpose": record.purpose if record else (purpose or ""),
        "destination": _masked(record.channel, record.destination) if record else None,
        "status": state,
        "expires_in": remaining,
        "resend_in": otp_service.cooldown_left(
            record.user_id, record.purpose, record.channel) if record else 0,
        "attempts_left": record.attempts_left() if record else 0,
        "max_attempts": record.max_attempts if record else otp_service.max_attempts(),
        "otp_length": otp_service.code_length(),
        "expires_minutes": otp_service.expiration_minutes(),
    }
    if message:
        payload["message"] = message
    return payload


def _send(user, channel, purpose, recipient_id=None):
    """Issue a challenge and deliver it. Returns the stored record."""
    destination = user.email if channel == CHANNEL_EMAIL else user.phone_number
    record, code = otp_service.create_challenge(
        user.id, channel, purpose, destination, recipient_id=recipient_id)
    if channel == CHANNEL_EMAIL:
        row = notification_service.send_code_email(user, destination, code, purpose)
    else:
        row = notification_service.send_code_sms(user, destination, code, purpose)
    delivery = getattr(row, "status", "sent")
    if delivery != "sent":
        # Keep the challenge unusable: a code the user never received must not
        # sit there waiting to be guessed.
        record.invalidated_at = otp_service.utcnow()
        db.session.commit()
        raise DeliveryFailed(_delivery_message(channel, delivery, row))
    return record


def _delivery_message(channel, delivery, row=None):
    """Say exactly what is misconfigured, not just 'delivery failed'."""
    detail = str(getattr(row, "error_message", "") or "").strip()
    if channel == CHANNEL_EMAIL:
        if not email_service.is_configured():
            return ("Email sign-up is unavailable: this WSA instance has no mail server "
                    "configured. Ask the administrator to set MAIL_SERVER (and "
                    "MAIL_USERNAME / MAIL_PASSWORD) in .env, or sign up with a phone number.")
        return (f"The verification email could not be sent ({delivery})."
                + (f" {detail}" if detail else " Check the mail server settings in .env."))
    if sms_service.get_provider() is None:
        return ("Phone sign-up is unavailable: this WSA instance has no SMS provider "
                "configured. Ask the administrator to set SMS_PROVIDER (and the API "
                "credentials) in .env, or sign up with an email address.")
    return (f"The verification SMS could not be sent ({delivery})."
            + (f" {detail}" if detail else " Check the SMS provider settings in .env."))


def _rate_limited(scope, identity, config_key):
    limit, window = current_limit(config_key)
    allowed, retry = rate_limit.check(scope, identity, limit, window)
    return None if allowed else retry


def _register_blocked():
    """True when this client has already used its registration quota."""
    limit, window = current_limit("RATE_LIMIT_REGISTER")
    return rate_limit.peek("register", _client_ip(), limit, window) <= 0


def current_limit(config_key):
    from flask import current_app
    return current_app.config.get(config_key, (5, 3600))


def verification_required():
    """Does this instance verify email addresses at all?"""
    from flask import current_app
    return bool(current_app.config.get("EMAIL_VERIFICATION_ENABLED", True))


def login_code_required():
    """Must a sign-in be finished with an emailed one-time code?"""
    from flask import current_app
    return (verification_required()
            and bool(current_app.config.get("LOGIN_OTP_ENABLED", True)))


# ------------------------------------------------------------------ pages ----

@bp.get("/login")
def login_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("login.html", title="Sign in",
                           otp_length=otp_service.code_length(),
                           email_code_required=login_code_required())


@bp.get("/register")
def register_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("register.html", title="Create account",
                           countries=country_options(),
                           default_country=default_country(),
                           roles=ROLE_OPTIONS, role_other=ROLE_OTHER)


@bp.get("/verify")
def verify_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    data = _pending()
    if data is None:
        if not session.get(RESET_REQUESTED_KEY):
            return redirect(url_for("auth.login_page"))
        # Neutral state: a code may or may not exist. Never reveal which.
        return render_template("verify.html", title="Verify your account", channel=None,
                               purpose=PURPOSE_PASSWORD_RESET, destination=None,
                               expires_in=0, resend_in=0,
                               otp_length=otp_service.code_length(),
                               dev_mailbox=email_service.dev_mailbox(),
                               generic=True)
    record = _pending_challenge()
    channel = data["channel"]
    title = ("Verify your sign-in" if data["purpose"] == PURPOSE_LOGIN_VERIFICATION
             else "Verify your account")
    return render_template("verify.html", title=title,
                           channel=channel, purpose=data["purpose"],
                           destination=_masked(channel, data["destination"]),
                           expires_in=otp_service.status_for(record)[1],
                           resend_in=otp_service.cooldown_left(
                               data["user_id"], data["purpose"], channel),
                           otp_length=otp_service.code_length(),
                           dev_mailbox=email_service.dev_mailbox(),
                           generic=False)


@bp.get("/forgot-password")
def forgot_password_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    return render_template("forgot_password.html", title="Reset password")


@bp.get("/reset-password")
def reset_password_page():
    if current_user.is_authenticated:
        return redirect(url_for("main.dashboard"))
    if not session.get(RESET_OK_KEY):
        return redirect(url_for("auth.forgot_password_page"))
    return render_template("reset_password.html", title="Choose a new password")


@bp.get("/logout")
@login_required
def logout():
    logout_user()
    _clear_pending()
    return redirect(url_for("auth.login_page"))


# ------------------------------------------------------------ registration ----

class DeliveryFailed(Exception):
    """The code could not be handed to the email/SMS provider."""


@bp.post("/api/auth/register")
def register():
    data = request.get_json(silent=True) or {}
    channel = str(data.get("channel") or CHANNEL_EMAIL).strip().lower()
    if channel not in VALID_CHANNELS:
        return jsonify(error="Choose whether to sign up with email or phone."), 400

    # The quota is only consumed once a code is actually delivered (see below),
    # so a misconfigured mail server can never lock the operator out of the
    # sign-up form. Whether the channel even works is decided by the delivery
    # layer, which reports a specific, actionable reason.
    if _register_blocked():
        return jsonify(error="Registration limit reached for your network. "
                             "Try again in a few minutes."), 429

    password = data.get("password") or ""
    confirm = data.get("confirm_password")
    if confirm not in (None, "") and confirm != password:
        return jsonify(error="Passwords do not match."), 400
    problem = _password_problem(password)
    if problem:
        return jsonify(error=problem), 400

    role = _resolved_role(data)
    if role is None:
        return jsonify(error="Choose the role that describes you best."), 400

    email = phone = ""
    if channel == CHANNEL_EMAIL:
        email = str(data.get("email") or "").strip().lower()
        if not EMAIL_RE.match(email):
            return jsonify(error="Enter a valid email address."), 400
    else:
        try:
            phone = normalize(str(data.get("phone_number") or "").strip(),
                              data.get("country") or None)
        except PhoneError as exc:
            return jsonify(error=str(exc)), 400

    username = str(data.get("username") or "").strip() or _default_username(email, phone)
    if not 2 <= len(username) <= 80:
        return jsonify(error="Enter a name of at least 2 characters, or leave it blank "
                             "and we will use your email address."), 400

    conflict = (User.query.filter(db.func.lower(User.email) == email).first() if email
                else User.query.filter_by(phone_number=phone).first())
    if conflict is not None:
        return jsonify(error="An account already exists for that contact. Try signing in."), 409
    if User.query.filter(db.func.lower(User.username) == username.lower()).first():
        username = f"{username}-{phone[-4:]}" if phone else f"{username}-{email.split('@')[0][:8]}"

    user = User(
        username=username,
        email=email or None,
        phone_number=phone or None,
        role=role,
        email_verified=False,
        phone_verified=False,
        primary_auth_method=channel,
    )
    user.set_password(password)
    db.session.add(user)
    try:
        db.session.commit()
    except IntegrityError:
        # A unique constraint fired (usually a sign-up that raced another for the
        # same email/phone, or an out-of-date schema). Answer with a clear message
        # instead of letting it become an opaque 500.
        db.session.rollback()
        return jsonify(error="That account could not be created because the email "
                             "address or phone number is already registered. "
                             "Try signing in instead."), 409

    if not verification_required():
        # No verification on this instance: the account is usable straight away -
        # no code is sent, so no mail server or SMS provider is needed at all.
        user.email_verified = bool(user.email)
        user.phone_verified = bool(user.phone_number)
        db.session.commit()
        _rate_limited("register", _client_ip(), "RATE_LIMIT_REGISTER")
        login_user(LoginUser(user), remember=bool(data.get("remember")))
        _after_login(user)
        return jsonify(message="Account created. Welcome to WSA!",
                       next=url_for("main.dashboard"), user=user.to_dict()), 200

    try:
        record = _send(user, channel, PURPOSE_ACCOUNT_VERIFICATION)
    except DeliveryFailed as exc:
        db.session.delete(user)  # never leave an unverified account behind
        db.session.commit()
        # Deliberately NOT consuming the registration quota here: a delivery
        # failure is an operator/configuration problem, and charging the
        # operator for it is what previously locked them out of sign-up.
        return jsonify(error=str(exc)), 503
    _rate_limited("register", _client_ip(), "RATE_LIMIT_REGISTER")
    _set_pending(user, channel, PURPOSE_ACCOUNT_VERIFICATION, record.id,
                 user.email or user.phone_number)
    payload = _challenge_payload(record, purpose=PURPOSE_ACCOUNT_VERIFICATION,
                                message="Account created. Enter the code we sent you.")
    payload["next"] = url_for("auth.verify_page")
    payload["message"] = "Verification code sent."
    return jsonify(**payload), 201


def _resolved_role(data):
    """The role the visitor chose, or ``None`` when their answer is missing.

    "Other" is replaced by the short description they typed, so the stored label
    is still meaningful to whoever reads the account list later.
    """
    role = str(data.get("role") or "").strip()
    if role == ROLE_OTHER:
        custom = str(data.get("role_other") or "").strip()
        if not 2 <= len(custom) <= 40:
            return None
        return custom
    if role not in ROLE_OPTIONS:
        return None
    return role


def _default_username(email, phone):
    if email:
        return email.split("@")[0][:80]
    return f"user{phone[-6:]}"


# ------------------------------------------------------------ verification ----

@bp.post("/api/auth/send-verification-code")
def send_verification_code():
    """Issue the first code for a freshly registered account."""
    return _issue_code(allow_new=True)


@bp.post("/api/auth/resend-verification-code")
def resend_verification_code():
    """Re-send the code for the challenge this session is answering."""
    return _issue_code(allow_new=False)


def _issue_code(allow_new):
    data = request.get_json(silent=True) or {}
    channel = str(data.get("channel") or "").strip().lower() or None
    pending = _pending()
    if pending is None:
        return jsonify(error="Start again from the sign-up or password reset page."), 400
    if channel and channel != pending["channel"]:
        return jsonify(error="That verification channel does not match this request."), 400

    user = db.session.get(User, pending["user_id"])
    if user is None:
        _clear_pending()
        return jsonify(error="Start again from the sign-up or password reset page."), 400

    identity = f"{user.id}:{pending['channel']}"
    # Checked before consuming, so a failed delivery cannot exhaust the quota
    # and strand the user with no way to retry.
    limit, window = current_limit("RATE_LIMIT_OTP_SEND")
    if rate_limit.peek("otp_send", identity, limit, window) <= 0:
        return jsonify(error="You have requested many codes already. "
                             "Please wait before requesting another."), 429

    cooldown = otp_service.cooldown_left(user.id, pending["purpose"], pending["channel"])
    if cooldown > 0:
        payload = _challenge_payload(_pending_challenge(), pending["purpose"],
                                     message="A code was sent recently.")
        payload["next"] = url_for("auth.verify_page")
        return jsonify(**payload), 429

    try:
        record = _send(user, pending["channel"], pending["purpose"])
    except DeliveryFailed as exc:
        return jsonify(error=str(exc)), 503
    _rate_limited("otp_send", identity, "RATE_LIMIT_OTP_SEND")
    # The masked destination shown in the UI must belong to the channel the code
    # travels on, not simply to the account's email address.
    destination = user.email if pending["channel"] == CHANNEL_EMAIL else user.phone_number
    _set_pending(user, pending["channel"], pending["purpose"], record.id, destination,
                 allow_mfa=pending.get("allow_mfa"), allow_reset=pending.get("allow_reset"))
    payload = _challenge_payload(record, message="A new verification code has been sent.")
    payload["next"] = url_for("auth.verify_page")
    return jsonify(**payload), 200


@bp.post("/api/auth/verify-code")
def verify_code():
    data = request.get_json(silent=True) or {}
    code = str(data.get("code") or "").strip()
    channel = str(data.get("channel") or "").strip().lower() or None

    pending = _pending()
    if pending is None:
        return jsonify(error=GENERIC_INVALID_CODE), 400
    if channel and channel != pending["channel"]:
        # Do not confirm which channels exist on the account.
        return jsonify(error=GENERIC_INVALID_CODE), 400

    identity = f"{pending['user_id']}:{pending['channel']}"
    retry = _rate_limited("otp_verify", identity, "RATE_LIMIT_OTP_VERIFY")
    if retry:
        return jsonify(error="Too many verification attempts. Try again later."), 429

    user = db.session.get(User, pending["user_id"])
    if user is None:
        _clear_pending()
        return jsonify(error=GENERIC_INVALID_CODE), 400

    record = db.session.get(VerificationCode, pending["challenge_id"])
    ok, message = otp_service.verify(record, code)
    if not ok:
        return jsonify(error=message, **_challenge_payload(record, pending["purpose"])), 400

    if pending["purpose"] == PURPOSE_PASSWORD_RESET:
        session[RESET_OK_KEY] = True
        return jsonify(message="Code accepted. Choose a new password.",
                       next=url_for("auth.reset_password_page"))

    if pending["purpose"] == PURPOSE_LOGIN_VERIFICATION:
        login_user(LoginUser(user), remember=bool(session.get("remember_me")))
        _after_login(user)
        _clear_pending()
        return jsonify(message="Signed in.", next=url_for("main.dashboard"),
                       user=user.to_dict())

    if pending["purpose"] == PURPOSE_ACCOUNT_VERIFICATION:
        if pending["channel"] == CHANNEL_EMAIL and user.email:
            user.email_verified = True
        elif pending["channel"] == CHANNEL_PHONE and user.phone_number:
            user.phone_verified = True
        user.primary_auth_method = pending["channel"]
        user.is_active = True
        db.session.commit()
        login_user(LoginUser(user), remember=bool(session.get("remember_me")))
        _clear_pending()
        return jsonify(message="Your account is verified. Welcome to WSA!",
                       next=url_for("main.dashboard"), user=user.to_dict())

    _clear_pending()
    return jsonify(message="Verification successful.")


GENERIC_INVALID_CODE = "The verification code is invalid or has expired."


# ------------------------------------------------------------------ login ----

def _find_user(identifier):
    """Resolve an email, phone number or username.

    Returns ``(row, channel)`` where channel is ``email``/``phone`` when the
    identifier matched a contact channel, or ``None`` for a username match.
    """
    value = identifier.strip()
    lowered = value.lower()
    if EMAIL_RE.match(lowered):
        row = User.query.filter(db.func.lower(User.email) == lowered).first()
        if row is not None:
            return row, CHANNEL_EMAIL
    if PHONE_HINT.search(value):
        try:
            normalised = normalize(value)
        except PhoneError:
            normalised = None
        if normalised:
            row = User.query.filter_by(phone_number=normalised).first()
            if row is not None:
                return row, CHANNEL_PHONE
    return User.query.filter(db.func.lower(User.username) == lowered).first(), None


def _login_channel(user, matched):
    """Which verified contact receives the sign-in code.

    The channel the visitor actually signed in with wins - signing in with an
    email address mails the code to that address - and only then falls back to
    the account's first verified channel. ``verified_channels()`` is never empty
    here: an account without a verified contact is refused before this point.
    """
    available = user.verified_channels()
    if matched:
        for channel, destination in available:
            if channel == matched:
                return channel, destination
    return available[0]


def _resume_verification(user, channel):
    """Issue a fresh account-verification code for a *correct* password.

    Only reachable with the right password, so it reveals nothing about which
    accounts exist. Without it an expired sign-up code stranded the account
    forever: registration refuses the duplicate address and sign-in refused the
    unverified one, leaving no way to ask for another code.
    """
    identity = f"{user.id}:{channel}"
    limit, window = current_limit("RATE_LIMIT_OTP_SEND")
    if rate_limit.peek("otp_send", identity, limit, window) <= 0:
        return jsonify(error="You have requested many codes already. "
                             "Please wait before requesting another."), 429
    try:
        record = _send(user, channel, PURPOSE_ACCOUNT_VERIFICATION)
    except DeliveryFailed as exc:
        return jsonify(error=str(exc)), 503
    _rate_limited("otp_send", identity, "RATE_LIMIT_OTP_SEND")
    destination = user.email if channel == CHANNEL_EMAIL else user.phone_number
    _set_pending(user, channel, PURPOSE_ACCOUNT_VERIFICATION, record.id, destination)
    payload = _challenge_payload(
        record, purpose=PURPOSE_ACCOUNT_VERIFICATION,
        message="This account is not verified yet. We sent a new code.")
    payload["next"] = url_for("auth.verify_page")
    return jsonify(**payload), 200


@bp.post("/api/auth/login")
def login():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    password = data.get("password") or ""
    if not identifier or not password:
        return jsonify(error="Enter your email or phone number and password."), 400

    retry = _rate_limited("login", _client_ip(), "RATE_LIMIT_LOGIN")
    if retry:
        return jsonify(error="Too many sign-in attempts. Try again later."), 429

    user, channel = _find_user(identifier)
    # One generic failure for unknown account or wrong password: this must not
    # let anyone enumerate accounts.
    generic = jsonify(error="Invalid credentials, or this account is not verified yet."), 401
    if user is None or not user.check_password(password) or not user.is_active:
        return generic
    if not verification_required():
        # Password-only by explicit configuration: nothing is emailed, and no
        # account state can stand between a correct password and the workspace.
        return _password_only_login(user, data)
    # A correct password on a contact that was never verified is not a dead end:
    # the sign-up code may simply have expired, so a fresh one is issued here and
    # the visitor finishes on the verification page.
    if channel == CHANNEL_EMAIL and user.email and not user.email_verified:
        return _resume_verification(user, CHANNEL_EMAIL)
    if channel == CHANNEL_PHONE and user.phone_number and not user.phone_verified:
        return _resume_verification(user, CHANNEL_PHONE)
    if not user.verified_channels():
        return _resume_verification(user, CHANNEL_EMAIL if user.email else CHANNEL_PHONE)

    session["remember_me"] = bool(data.get("remember"))
    if login_code_required():
        challenge_channel, destination = _login_channel(user, channel)
        try:
            record = _send(user, challenge_channel, PURPOSE_LOGIN_VERIFICATION)
        except DeliveryFailed as exc:
            # No code, no session: a mail problem must never become a bypass.
            return jsonify(error=str(exc)), 503
        _set_pending(user, challenge_channel, PURPOSE_LOGIN_VERIFICATION, record.id,
                     destination, allow_mfa=True)
        payload = _challenge_payload(
            record, message=f"Enter the {otp_service.code_length()}-digit code we sent to "
                            f"{_masked(challenge_channel, destination)}.")
        payload["next"] = url_for("auth.verify_page")
        payload["mfa"] = True
        return jsonify(**payload), 200

    return _password_only_login(user, data)


def _password_only_login(user, data):
    """Open the session without an emailed code (sign-in verification is off)."""
    login_user(LoginUser(user), remember=bool(data.get("remember")))
    _after_login(user)
    return jsonify(message=f"Welcome back, {user.username}!", next=url_for("main.dashboard"),
                   user=user.to_dict())


def _after_login(user):
    user.last_login_at = otp_service.utcnow()
    user.last_login_ip = _client_ip()
    db.session.commit()
    try:
        notification_service.notify_login(
            user, ip_address=_client_ip(),
            user_agent=request.headers.get("User-Agent", "")[:200] or None,
            browser=_browser_name(request.headers.get("User-Agent", "")),
            os_name=_os_name(request.headers.get("User-Agent", "")))
    except Exception as exc:  # a notification failure never blocks a login
        log.warning("login notification failed: %s", exc)


def _browser_name(user_agent):
    ua = (user_agent or "").lower()
    for needle, name in (("edg/", "Edge"), ("opr/", "Opera"), ("chrome/", "Chrome"),
                         ("firefox/", "Firefox"), ("safari/", "Safari")):
        if needle in ua:
            return name
    return None


def _os_name(user_agent):
    ua = (user_agent or "").lower()
    for needle, name in (("windows", "Windows"), ("android", "Android"), ("iphone", "iOS"),
                         ("ipad", "iPadOS"), ("mac os", "macOS"), ("linux", "Linux")):
        if needle in ua:
            return name
    return None


@bp.post("/api/auth/logout")
@api_login_required
def logout_api():
    logout_user()
    _clear_pending()
    return jsonify(message="Signed out.")


@bp.get("/api/auth/session")
def session_state():
    row = current_row()
    if row is None:
        return jsonify(authenticated=False)
    return jsonify(authenticated=True, user=row.to_dict(),
                   channels=[{"channel": c, "destination": _masked(c, d)}
                             for c, d in row.verified_channels()])


# --------------------------------------------------------- password reset ----

@bp.post("/api/auth/forgot-password")
def forgot_password():
    data = request.get_json(silent=True) or {}
    identifier = (data.get("identifier") or "").strip()
    channel = str(data.get("channel") or "").strip().lower() or None
    if not identifier:
        return jsonify(error="Enter the email address or phone number on your account."), 400
    if channel and channel not in VALID_CHANNELS:
        return jsonify(error="Unsupported verification channel."), 400

    retry = _rate_limited("password_reset", _client_ip(), "RATE_LIMIT_PASSWORD_RESET")
    if retry:
        # Rate limiting is itself a side channel; keep the message generic.
        return jsonify(message=GENERIC_RESET_MESSAGE, next="/verify"), 200

    _clear_pending()
    session[RESET_REQUESTED_KEY] = True
    user, _channel = _find_user(identifier)
    channels = []
    if user is not None:
        available = user.verified_channels()
        chosen = None
        if channel:
            chosen = next((c for c in available if c[0] == channel), None)
        elif len(available) == 1:
            chosen = available[0]
        if chosen:
            try:
                record = _send(user, chosen[0], PURPOSE_PASSWORD_RESET)
            except DeliveryFailed as exc:
                log.warning("password reset code not delivered: %s", exc)
            else:
                _set_pending(user, chosen[0], PURPOSE_PASSWORD_RESET, record.id,
                             chosen[1], allow_reset=True)
        # Only the requester's own, already-verified channels are listed; when
        # several exist the user picks one in the UI.
        channels = _reset_channels(user)

    return jsonify(message=GENERIC_RESET_MESSAGE, next="/verify", channels=channels), 200


GENERIC_RESET_MESSAGE = ("If an account exists for this information, a verification code "
                         "has been sent.")


def _reset_channels(user):
    return [{"channel": c, "destination": _masked(c, d)} for c, d in user.verified_channels()]


@bp.post("/api/auth/reset-password")
def reset_password():
    data = request.get_json(silent=True) or {}
    password = data.get("password") or ""
    confirm = data.get("confirm_password")
    if not session.get(RESET_OK_KEY):
        return jsonify(error="Verify your code before setting a new password."), 403
    pending = _pending()
    user = db.session.get(User, pending["user_id"]) if pending else None
    if user is None:
        _clear_pending()
        return jsonify(error="Start the password reset again."), 400
    if confirm not in (None, "") and confirm != password:
        return jsonify(error="Passwords do not match."), 400
    problem = _password_problem(password)
    if problem:
        return jsonify(error=problem), 400

    user.set_password(password)
    user.last_login_at = None
    db.session.commit()
    _clear_pending()
    return jsonify(message="Your password has been changed. Sign in with the new password.")


# ---------------------------------------------------------------- profile ----

@bp.get("/api/auth/me")
@api_login_required
def me():
    row = current_row()
    return jsonify(user=row.to_dict(), channels=_reset_channels(row))
