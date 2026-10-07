"""A new account starts empty and never sees another account's data.

Every dashboard, findings, scan, report and network-scan query is scoped to the
signed-in user. These tests create data for one account and prove a second
account sees none of it - a clean dashboard - while the owner still sees it.
"""
from tests.conftest import register_and_verify


def _sign_up(app, otp_box, email, username):
    """Register + verify on a *separate* client, returning that signed-in client."""
    client = app.test_client()
    register_and_verify(client, otp_box, email=email, username=username)
    return client


def _add_alice_scan(app):
    """Give Alice one completed scan with one high finding; return the scan id."""
    from app.extensions import db
    from app.models import Scan, User, Vulnerability

    with app.app_context():
        alice = User.query.filter_by(email="alice@example.com").first()
        scan = Scan(target_url="https://alice.example", scan_type="quick",
                    status="completed", progress=100, user_id=alice.id)
        db.session.add(scan)
        db.session.commit()
        db.session.add(Vulnerability(scan_id=scan.id, name="Reflected XSS",
                                     severity="high", target_url=scan.target_url))
        db.session.commit()
        return scan.id


def test_new_user_dashboard_is_empty(app, otp_box):
    alice = _sign_up(app, otp_box, "alice@example.com", "Alice")
    scan_id = _add_alice_scan(app)

    # Alice sees her own scan and finding.
    summary = alice.get("/api/dashboard/summary").get_json()
    assert summary["total_scans_all"] == 1
    assert summary["total_findings"] == 1
    assert summary["empty"] is False

    bob = _sign_up(app, otp_box, "bob@example.com", "Bob")
    summary = bob.get("/api/dashboard/summary").get_json()
    assert summary["total_scans_all"] == 0
    assert summary["total_findings"] == 0
    assert summary["empty"] is True

    assert bob.get("/api/scans").get_json()["scans"] == []
    assert bob.get("/api/vulnerabilities").get_json()["total"] == 0
    assert bob.get("/api/targets").get_json()["targets"] == []


def test_another_users_scan_is_not_readable(app, otp_box):
    alice = _sign_up(app, otp_box, "alice2@example.com", "Alice Two")
    scan_id = _add_alice_scan_for(app, "alice2@example.com")

    # The owner can read it; a different account must not even know it exists.
    assert alice.get(f"/api/scans/{scan_id}").status_code == 200

    bob = _sign_up(app, otp_box, "bob2@example.com", "Bob Two")
    assert bob.get(f"/api/scans/{scan_id}").status_code == 404
    assert bob.delete(f"/api/scans/{scan_id}").status_code == 404

    # Alice's scan survived Bob's attempt.
    assert alice.get(f"/api/scans/{scan_id}").status_code == 200


def _add_alice_scan_for(app, email):
    from app.extensions import db
    from app.models import Scan, User

    with app.app_context():
        owner = User.query.filter_by(email=email).first()
        scan = Scan(target_url="https://private.example", scan_type="quick",
                    status="completed", user_id=owner.id)
        db.session.add(scan)
        db.session.commit()
        return scan.id
