"""Notification bodies must be buildable from real rows.

Regression: ``notify_login`` passed a list of pre-formatted strings to code that
unpacked ``(key, value)`` pairs, so every login raised
``TypeError: too many values to unpack`` and the security alert was silently
swallowed by the scanner's notification guard.
"""
import pytest

from app.models import User
from app.services import email_service, notification_service


def _user(app, **kw):
    from app.extensions import db
    with app.app_context():
        user = User(username="Notifier", email="notifier@wsa.local",
                    email_verified=True, phone_number="+250788123456",
                    phone_verified=True, primary_auth_method="email")
        user.set_password("secret123")
        for k, v in kw.items():
            setattr(user, k, v)
        db.session.add(user)
        db.session.commit()
        return user.id


@pytest.fixture()
def captured_email(monkeypatch):
    sent = []
    monkeypatch.setattr(email_service, "send_email",
                        lambda *a, **k: sent.append({"to": a[0] if a else k.get("recipient"),
                                                    "subject": a[1] if len(a) > 1 else k.get("subject"),
                                                    "html": a[2] if len(a) > 2 else k.get("html_body")})
                        or _Row())
    return sent


class _Row:
    status = "sent"
    recipient = "captured"
    error_message = ""


def test_login_alert_builds_without_raising(app, captured_email):
    user_id = _user(app)
    from app.extensions import db
    with app.test_request_context(headers={"User-Agent": "Mozilla/5.0 (Windows NT 10.0)"}):
        user = db.session.get(User, user_id)
        rows = notification_service.notify_login(
            user, ip_address="203.0.113.9", user_agent="Mozilla/5.0 (Windows NT 10.0)")
    # One email (captured) plus one SMS: both channels are verified and enabled.
    assert len(rows) == 2
    assert captured_email[0]["to"] == "notifier@wsa.local"
    assert "203.0.113.9" in captured_email[0]["html"]
    assert "Windows" in captured_email[0]["html"]


def test_scan_completed_email_quotes_the_real_scan(app, captured_email):
    from app.extensions import db
    from app.models import Scan, Vulnerability
    with app.app_context():
        user_id = _user(app)
        scan = Scan(target_url="https://example.test", status="completed", user_id=user_id)
        db.session.add(scan)
        db.session.commit()
        db.session.add(Vulnerability(scan_id=scan.id, name="Real finding",
                                     severity="medium", target_url="https://example.test"))
        db.session.commit()
        rows = notification_service.notify_scan_completed(scan)

    assert any(getattr(r, "status", None) == "sent" for r in rows)
    html = captured_email[0]["html"]
    assert "https://example.test" in html
    assert "Real finding" not in html  # the summary lists counts, not invented names
    assert "Medium" in html


def test_opt_out_suppresses_both_channels(app, captured_email):
    from app.extensions import db
    with app.app_context():
        user_id = _user(app)
        notification_service.set_preferences(user_id, {"new_login_alert": False},
                                             {"new_login_alert": False})
        user = db.session.get(User, user_id)
        assert notification_service.notify_login(user, ip_address="198.51.100.1") == []
    assert captured_email == []


def test_opting_out_of_email_still_allows_sms(app, captured_email):
    from app.extensions import db
    with app.app_context():
        user_id = _user(app)
        notification_service.set_preferences(user_id, {"new_login_alert": False}, {})
        user = db.session.get(User, user_id)
        rows = notification_service.notify_login(user, ip_address="198.51.100.2")
    assert captured_email == []
    assert len(rows) == 1, "SMS is a separate opt-in and stays on"


def test_report_refuses_an_unverified_recipient(app):
    from app.extensions import db
    from app.models import Scan
    with app.app_context():
        user_id = _user(app)
        scan = Scan(target_url="https://example.test", status="completed", user_id=user_id)
        db.session.add(scan)
        db.session.commit()
        rows = notification_service.deliver_report(
            scan, "reports/x.pdf", [{"email": "stranger@evil.test"}])
    assert rows == [], "scan data must never reach an unverified address"
