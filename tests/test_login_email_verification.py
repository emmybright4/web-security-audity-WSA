"""Sign-in is email + password + an emailed one-time code.

The shipped default (``LOGIN_OTP_ENABLED=true``) makes a correct password only
step one: until the code from the account's inbox is accepted the visitor has no
session, and a mail server that cannot deliver *refuses* the sign-in instead of
letting it through.
"""
import pytest

from .conftest import register_and_verify

EMAIL = "signin@wsa.local"
PASSWORD = "secret123"
USERNAME = "Signin Tester"


@pytest.fixture()
def email_code_login(app):
    """Force the shipped default, independent of the machine's .env."""
    app.config["LOGIN_OTP_ENABLED"] = True
    return app


def _account(client, otp_box, *, email=EMAIL, username=USERNAME, password=PASSWORD):
    """A verified account, with the registration session already closed."""
    register_and_verify(client, otp_box, username=username, email=email, password=password)
    assert client.post("/api/auth/logout").status_code == 200
    return client


def _login(client, identifier=EMAIL, password=PASSWORD, **extra):
    payload = {"identifier": identifier, "password": password}
    payload.update(extra)
    return client.post("/api/auth/login", json=payload)


def _signed_in(client):
    return client.get("/api/auth/session").get_json()["authenticated"]


def test_password_step_emails_a_code_and_creates_no_session(email_code_login, client, otp_box):
    _account(client, otp_box)

    resp = _login(client)

    assert resp.status_code == 200, resp.get_data(as_text=True)
    payload = resp.get_json()
    assert payload["mfa"] is True and payload["next"] == "/verify"
    assert payload["channel"] == "email"
    challenge = otp_box[-1]
    assert challenge["purpose"] == "login_verification"
    assert challenge["destination"] == EMAIL
    # the password alone must not open the workspace
    assert _signed_in(client) is False
    assert client.get("/").status_code == 302
    # ... and the visitor lands on the code page, worded as a sign-in
    page = client.get("/verify").get_data(as_text=True)
    assert "Finish signing in" in page and "sign-in code" in page


def test_the_emailed_code_completes_the_sign_in(email_code_login, client, otp_box):
    _account(client, otp_box)
    _login(client)

    code = otp_box[-1]["code"]
    verified = client.post("/api/auth/verify-code", json={"code": code, "channel": "email"})

    assert verified.status_code == 200, verified.get_data(as_text=True)
    assert verified.get_json()["next"] == "/"
    assert _signed_in(client) is True
    assert USERNAME in client.get("/").get_data(as_text=True)


def test_a_wrong_code_never_signs_anyone_in(email_code_login, client, otp_box):
    _account(client, otp_box)
    _login(client)
    wrong = "111111" if otp_box[-1]["code"] != "111111" else "222222"

    rejected = client.post("/api/auth/verify-code", json={"code": wrong})

    assert rejected.status_code == 400
    assert _signed_in(client) is False


def test_the_code_goes_to_the_email_used_to_sign_in(app, email_code_login, client, otp_box):
    """An account verified on both channels still gets the code at the email."""
    _account(client, otp_box)
    with app.app_context():
        from app.extensions import db
        from app.models import User
        row = User.query.filter_by(email=EMAIL).first()
        row.phone_number = "+250788999111"
        row.phone_verified = True
        db.session.commit()

    _login(client)

    challenge = otp_box[-1]
    assert challenge["channel"] == "email"
    assert challenge["destination"] == EMAIL


def test_a_broken_mail_server_refuses_the_sign_in(app, email_code_login, client, otp_box,
                                                  monkeypatch):
    """Delivery failure is a 503, never a silent password-only sign-in."""
    _account(client, otp_box)
    # An SMTP server *is* configured here, so the failure is reported as a failed
    # send rather than as "no mail server" - either way the sign-in must refuse.
    app.config["MAIL_SERVER"] = "smtp.example.invalid"
    from app.services import notification_service

    def boom(*_a, **_k):
        from tests.test_notifications import _Row
        row = _Row()
        row.status = "failed"
        row.error_message = "simulated SMTP failure"
        return row

    monkeypatch.setattr(notification_service, "send_code_email", boom)

    resp = _login(client)

    assert resp.status_code == 503, resp.get_data(as_text=True)
    assert "verification email could not be sent" in resp.get_json()["error"]
    assert _signed_in(client) is False


def test_resend_issues_a_fresh_code_for_the_sign_in(app, email_code_login, client, otp_box):
    app.config["OTP_RESEND_COOLDOWN_SECONDS"] = 0  # exercise the code, not the timer
    _account(client, otp_box)
    _login(client)
    first = otp_box[-1]["code"]

    again = client.post("/api/auth/resend-verification-code", json={"channel": "email"})

    assert again.status_code == 200, again.get_data(as_text=True)
    second = otp_box[-1]["code"]
    assert second != first
    # the superseded code is dead, the new one works
    assert client.post("/api/auth/verify-code", json={"code": first}).status_code == 400
    assert client.post("/api/auth/verify-code", json={"code": second}).status_code == 200
    assert _signed_in(client) is True


def _unverified_account(app, email="unverified@wsa.local", username="Unverified Person"):
    """An account whose sign-up code was never entered (or has since expired)."""
    with app.app_context():
        from app.extensions import db
        from app.models import User
        user = User(username=username, email=email, email_verified=False,
                    primary_auth_method="email")
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()


def test_an_unverified_account_gets_a_new_code_instead_of_a_dead_end(email_code_login, app,
                                                                     client, otp_box):
    """Regression: an expired sign-up code used to strand the account for good.

    Registration refuses the duplicate address and sign-in refused the unverified
    account, so there was no way left to ever receive another code.
    """
    _unverified_account(app)

    resp = _login(client, identifier="unverified@wsa.local")

    assert resp.status_code == 200, resp.get_data(as_text=True)
    payload = resp.get_json()
    assert payload["next"] == "/verify"
    assert payload["purpose"] == "account_verification"
    assert otp_box[-1]["destination"] == "unverified@wsa.local"
    assert _signed_in(client) is False  # nothing opens until the code is entered
    verified = client.post("/api/auth/verify-code", json={"code": otp_box[-1]["code"]})
    assert verified.status_code == 200, verified.get_data(as_text=True)
    assert _signed_in(client) is True


def test_a_wrong_password_gets_the_generic_refusal_and_no_code(email_code_login, app, client,
                                                              otp_box):
    """That recovery path must not become an account-enumeration oracle."""
    _unverified_account(app)

    resp = _login(client, identifier="unverified@wsa.local", password="not-the-password")

    assert resp.status_code == 401
    assert otp_box == []


def test_password_only_sign_in_can_be_switched_off(client, app, otp_box):
    app.config["LOGIN_OTP_ENABLED"] = False
    _account(client, otp_box)

    resp = _login(client)

    assert resp.status_code == 200
    assert "mfa" not in resp.get_json()
    assert _signed_in(client) is True


def test_the_sign_in_email_reads_as_a_sign_in(app, monkeypatch):
    """A sign-in code must not arrive looking like a sign-up verification."""
    from app.services import email_service, notification_service

    sent = {}

    class _Row:
        status = "sent"
        error_message = ""

    def capture(recipient, subject, html_body, text_body=None, **_kw):
        sent.update(subject=subject, html=html_body)
        return _Row()

    monkeypatch.setattr(email_service, "send_email", capture)
    with app.test_request_context():
        from app.models import User
        user = User(username=USERNAME, email=EMAIL, email_verified=True)
        notification_service.send_code_email(user, EMAIL, "123456", "login_verification")

    assert "sign-in" in sent["subject"].lower()
    assert "signing in" in sent["html"]
    # code_block renders one <span> per digit
    assert all(f">{digit}</span>" in sent["html"] for digit in "123456")


def test_a_restart_never_verifies_an_account_that_did_not_finish(app, client, otp_box):
    """Regression: the startup backfill blessed every account that had an email.

    So a single server restart "verified" an account that had never entered a
    code, which silently disabled email verification.
    """
    from app import _backfill_verification

    _account(client, otp_box)  # a completed verification exists in the database
    _unverified_account(app, email="pending@wsa.local", username="Pending Person")

    with app.app_context():
        from app.models import User
        assert _backfill_verification(app) is None  # what every startup runs
        assert User.query.filter_by(email="pending@wsa.local").first().email_verified is False


def test_a_database_that_never_issued_a_code_still_trusts_its_accounts(app):
    """A genuinely pre-verification install must not lock its operator out."""
    from app import _backfill_verification

    with app.app_context():
        from app.extensions import db
        from app.models import User, VerificationCode
        assert VerificationCode.query.count() == 0  # nothing has ever been issued
        user = User(username="Old Timer", email="legacy@wsa.local", email_verified=False,
                    primary_auth_method="email")
        user.set_password(PASSWORD)
        db.session.add(user)
        db.session.commit()

    with app.app_context():
        from app.models import User
        _backfill_verification(app)
        assert User.query.filter_by(email="legacy@wsa.local").first().email_verified is True


def test_registration_needs_no_code_when_verification_is_off(app, client, otp_box):
    """The master switch removes sign-up verification too - not just sign-in."""
    app.config["EMAIL_VERIFICATION_ENABLED"] = False

    resp = client.post("/api/auth/register", json={
        "channel": "email", "email": "nolink@wsa.local", "username": "No Verifier",
        "role": "SOC Analyst",
        "password": PASSWORD, "confirm_password": PASSWORD})

    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert resp.get_json()["next"] == "/"
    assert otp_box == []  # nothing was ever emailed
    assert _signed_in(client) is True
    assert "No Verifier" in client.get("/").get_data(as_text=True)


def test_sign_in_needs_no_code_when_verification_is_off(app, client, otp_box):
    """An account that never proved its address can sign in here too."""
    app.config["EMAIL_VERIFICATION_ENABLED"] = False
    _unverified_account(app)

    resp = _login(client, identifier="unverified@wsa.local")

    assert resp.status_code == 200, resp.get_data(as_text=True)
    assert "mfa" not in resp.get_json()
    assert otp_box == []
    assert _signed_in(client) is True


def test_login_page_drops_the_code_promise_when_verification_is_off(app, client):
    """The page must not promise an email the instance will never send."""
    app.config["EMAIL_VERIFICATION_ENABLED"] = False

    html = client.get("/login").get_data(as_text=True)

    assert "one-time code" not in html
    assert "will be emailed to you" not in html


def test_login_page_announces_the_code(app, client):
    html = client.get("/login").get_data(as_text=True)
    assert 'type="email"' in html
    assert "will be emailed to you" in html

    app.config["LOGIN_OTP_ENABLED"] = False
    assert "will be emailed to you" not in client.get("/login").get_data(as_text=True)


def test_verify_page_says_where_a_development_code_went(app, email_code_login, client, otp_box):
    """Without SMTP the code cannot reach an inbox - the page must say where it is."""
    app.config["MAIL_SERVER"] = ""
    app.config["MAIL_FILE_DELIVERY"] = True
    app.config["MAIL_FILE_DIR"] = "instance/dev-mail"
    _account(client, otp_box)
    _login(client)

    page = client.get("/verify").get_data(as_text=True)

    assert "Development mail mode" in page
    assert "instance/dev-mail" in page


def test_verify_page_is_quiet_once_smtp_is_configured(app, email_code_login, client, otp_box):
    """A real mail server makes that hint false, so it must disappear."""
    app.config["MAIL_SERVER"] = "smtp.example.com"
    app.config["MAIL_FILE_DELIVERY"] = True
    app.config["MAIL_FILE_DIR"] = "instance/dev-mail"
    _account(client, otp_box)
    _login(client)

    page = client.get("/verify").get_data(as_text=True)

    assert "Development mail mode" not in page
    assert "instance/dev-mail" not in page
