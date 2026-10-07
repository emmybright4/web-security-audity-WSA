"""Registration must not lock the operator out of sign-up.

Regression: registration reused the OTP-send limit (5/hour) keyed only by client
IP. On a self-hosted instance every request comes from one IP, so after five
sign-ups the form returned "Too many attempts" for an hour - and because the
quota was charged before delivery, a misconfigured mail server (the real cause of
the failure) consumed the quota and masked itself behind that message.
"""
import pytest


def _register(client, n):
    return client.post("/api/auth/register", json={
        "channel": "email",
        "email": f"user{n}@example.com",
        "role": "SOC Analyst",
        "password": "secret123",
        "confirm_password": "secret123",
    })


def test_unconfigured_mail_never_returns_429(app, client):
    """With no SMTP and no local mailbox the answer is always the actionable 503.

    The configuration is stated here rather than inherited: a developer's .env
    may legitimately enable the file mailbox (MAIL_FILE_DELIVERY), which is not
    the situation this regression is about.
    """
    from app.services import rate_limit
    rate_limit.reset()
    app.config["MAIL_SERVER"] = ""
    app.config["MAIL_FILE_DELIVERY"] = False
    for n in range(12):
        resp = _register(client, n)
        assert resp.status_code == 503, f"attempt {n}: {resp.get_data(as_text=True)}"
        assert "no mail server configured" in resp.get_json()["error"]


def test_missing_sms_provider_is_reported_clearly(app, client):
    resp = client.post("/api/auth/register", json={
        "channel": "phone", "phone_number": "788123456", "country": "RW",
        "role": "SOC Analyst",
        "password": "secret123", "confirm_password": "secret123"})
    assert resp.status_code == 503
    assert "no SMS provider configured" in resp.get_json()["error"]


def test_quota_is_enforced_once_codes_are_actually_delivered(app, client, otp_box):
    from app.services import rate_limit
    rate_limit.reset()
    limit = app.config["RATE_LIMIT_REGISTER"][0]
    for n in range(limit):
        assert _register(client, n).status_code == 201, f"attempt {n} should succeed"
    blocked = _register(client, 999)
    assert blocked.status_code == 429
    assert "Registration limit reached" in blocked.get_json()["error"]


def test_failed_delivery_does_not_consume_the_quota(app, client, monkeypatch):
    """A broken provider must not charge the operator's quota."""
    from app.extensions import db
    from app.services import rate_limit
    rate_limit.reset()

    def boom(*a, **k):
        from tests.test_notifications import _Row
        row = _Row()
        row.status = "failed"
        return row

    monkeypatch.setattr("app.services.notification_service.send_code_email", boom)
    limit = app.config["RATE_LIMIT_REGISTER"][0]
    for n in range(limit + 5):
        assert _register(client, n).status_code == 503
    # No account may survive a failed registration.
    with app.app_context():
        from app.models import User
        assert User.query.filter(User.email.like("%@example.com")).count() == 0


def test_resend_quota_survives_failed_delivery(app, client, otp_box, monkeypatch):
    from app.extensions import db
    from app.services import rate_limit
    rate_limit.reset()
    # Remove the resend cooldown so this test exercises the *quota*, not the timer.
    app.config["OTP_RESEND_COOLDOWN_SECONDS"] = 0

    assert _register(client, 1).status_code == 201
    with app.app_context():
        from app.models import User
        assert User.query.count() >= 1

    def boom(*a, **k):
        from tests.test_notifications import _Row
        row = _Row()
        row.status = "failed"
        return row

    monkeypatch.setattr("app.services.notification_service.send_code_email", boom)
    limit = app.config["RATE_LIMIT_OTP_SEND"][0]
    for attempt in range(limit + 3):
        resp = client.post("/api/auth/resend-verification-code", json={"channel": "email"})
        assert resp.status_code == 503, (
            f"attempt {attempt} got {resp.status_code}: {resp.get_data(as_text=True)}")
