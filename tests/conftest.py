"""Shared pytest fixtures: an isolated app + SQLite DB per test session."""
import os
import sys
import tempfile

import pytest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))


@pytest.fixture()
def app(tmp_path):
    """A fresh WSA app with its own temporary database."""
    os.environ["DATABASE_URL"] = f"sqlite:///{(tmp_path / 'test.db').as_posix()}"

    # config.py caches DATABASE_URL at import time, so reload it after the env is set
    import importlib

    import config
    importlib.reload(config)

    from app import create_app

    app = create_app(config.Config)
    app.config["TESTING"] = True

    # The rate limiter is a process-wide singleton keyed by client IP, and the
    # test client is always 127.0.0.1. Without this reset, the login limit
    # trips part-way through a full run and later tests fail with 429.
    from app.services import rate_limit

    rate_limit.reset()

    yield app

    rate_limit.reset()
    # remove the seeded default user's lingering login session from the loader registry
    from flask_login import current_user  # noqa: F401


@pytest.fixture()
def client(app):
    return app.test_client()


@pytest.fixture(autouse=True)
def _shipped_auth_policy(app):
    """Pin the shipped security policy; a developer's .env must not change it.

    Two things are forced here: tests never touch SMTP or write into the
    developer's file mailbox, and the verification switches stay at their shipped
    defaults so an offline local .env cannot rewrite what the suite asserts.
    Tests *about* a switch set it explicitly.
    """
    app.config["MAIL_FILE_DELIVERY"] = False
    app.config["EMAIL_VERIFICATION_ENABLED"] = True
    app.config["LOGIN_OTP_ENABLED"] = True
    yield app


def sign_in(client, otp_box, identifier, password="wsa-admin-2026"):
    """Run the real sign-in: password -> emailed code -> session.

    Since sign-in verification shipped, a correct password is only step one. The
    code is read from the same seam the browser uses (the delivery layer), never
    from the database: only the hash is stored there.
    """
    resp = client.post("/api/auth/login",
                       json={"identifier": identifier, "password": password})
    assert resp.status_code == 200, f"sign-in failed: {resp.get_data(as_text=True)}"
    payload = resp.get_json() or {}
    if payload.get("mfa"):
        challenge = otp_box[-1]
        assert challenge["purpose"] == "login_verification", (
            f"expected a sign-in code, got {challenge['purpose']!r}")
        verified = client.post("/api/auth/verify-code",
                               json={"code": challenge["code"],
                                     "channel": challenge["channel"]})
        assert verified.status_code == 200, (
            f"sign-in code rejected: {verified.get_data(as_text=True)}")
    return payload


@pytest.fixture()
def auth_client(app, client, otp_box):
    """A test client signed in as the seeded default user, code and all."""
    sign_in(client, otp_box, "emmy.bright@wsa.local")
    return client


# --------------------------------------------------------------- OTP tests ---

class _Delivered:
    """Stand-in for an EmailLog/SmsLog row returned by the fake senders."""

    status = "sent"
    recipient = "captured"
    error_message = ""


@pytest.fixture()
def otp_box(monkeypatch):
    """Capture outgoing verification codes instead of contacting a gateway.

    Tests must never depend on a live SMTP server or SMS provider, and must
    never read a code from the database: only the real delivery layer sees the
    plaintext, so stubbing it here is the only seam that exists.
    """
    from app.services import notification_service

    delivered = []

    def fake_email(user, destination, code, purpose):
        delivered.append({"channel": "email", "destination": destination,
                          "code": code, "purpose": purpose})
        return _Delivered()

    def fake_sms(user, destination, code, purpose, scan_id=None):
        delivered.append({"channel": "phone", "destination": destination,
                          "code": code, "purpose": purpose})
        return _Delivered()

    monkeypatch.setattr(notification_service, "send_code_email", fake_email)
    monkeypatch.setattr(notification_service, "send_code_sms", fake_sms)
    return delivered


def register_and_verify(client, otp_box, *, channel="email", username="Test User",
                        email="tester@wsa.local", phone="+250788123456",
                        country="RW", password="secret123", accept=True):
    """Run the real sign-up flow and answer the real OTP challenge."""
    payload = {"username": username, "password": password,
               "confirm_password": password, "channel": channel}
    if channel == "email":
        payload["email"] = email
    else:
        payload["phone_number"] = phone
        payload["country"] = country
    resp = client.post("/api/auth/register", json=payload)
    assert resp.status_code == 201, resp.get_data(as_text=True)
    assert accept is not None
    code = otp_box[-1]["code"]
    verified = client.post("/api/auth/verify-code", json={"code": code, "channel": channel})
    assert verified.status_code == 200, verified.get_data(as_text=True)
    return verified.get_json()


@pytest.fixture()
def verified_user(client, otp_box):
    """A client signed in through the full registration + OTP flow."""
    def _make(**kwargs):
        return register_and_verify(client, otp_box, **kwargs)
    return _make

