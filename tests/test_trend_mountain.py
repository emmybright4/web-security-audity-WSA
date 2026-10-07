"""The main dashboard chart plots three real mountain series - nothing else.

mode=mountain is the data contract for the full-width Security Analytics
chart: Security Scans, Vulnerabilities Found and Critical Findings, one point
per bucket, every point a real row. These tests pin that contract the same way
test_trend_axis.py pins the types/severity views: no invented buckets, no
forecast tail, no fake values - and days with scans but zero findings still
render, because that is what the account's history honestly looks like.
"""
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Scan, User, Vulnerability

TREND = "/api/dashboard/vulnerability-trend"


def _add_scan(app, findings=(), days_ago=0):
    """One scan, optionally carrying (name, severity) findings."""
    with app.app_context():
        owner = User.query.filter_by(email="emmy.bright@wsa.local").first()
        when = (datetime.now(timezone.utc).replace(tzinfo=None)
                - timedelta(days=days_ago))
        scan = Scan(target_url="https://mountain.test", scan_type="quick",
                    status="completed", created_at=when, user_id=owner.id)
        db.session.add(scan)
        db.session.flush()
        for name, severity in findings:
            db.session.add(Vulnerability(
                name=name, severity=severity, scan_id=scan.id, created_at=when))
        db.session.commit()


def _series(data):
    return {s["key"]: s for s in data["series"]}


def test_mountain_is_empty_before_the_first_scan(auth_client):
    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    assert data["empty"] is True and data["dates"] == [] and data["series"] == []


def test_mountain_always_returns_exactly_three_series(auth_client, app):
    _add_scan(app, findings=[("SQL Injection", "high"),
                             ("Sitemap Present", "informational")])

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    assert data["empty"] is False
    assert [s["key"] for s in data["series"]] == [
        "vulnerabilities", "scans", "critical"]
    for s in data["series"]:
        assert len(s["data"]) == len(data["dates"])


def test_scans_are_counted_even_when_no_findings_exist(auth_client, app):
    """A scan with zero findings is still real history and must be plotted."""
    _add_scan(app)
    _add_scan(app, days_ago=3)

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    series = _series(data)
    assert series["scans"]["total"] == 2
    assert sum(series["scans"]["data"]) == 2
    assert sum(series["vulnerabilities"]["data"]) == 0
    assert sum(series["critical"]["data"]) == 0


def test_findings_and_critical_split_across_series(auth_client, app):
    _add_scan(app, findings=[("SQL Injection", "critical"),
                             ("XSS", "critical"),
                             ("Missing header", "high"),
                             ("Info leak", "low")])

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    series = _series(data)
    assert series["vulnerabilities"]["total"] == 4
    assert series["critical"]["total"] == 2
    assert series["scans"]["total"] == 1


def test_critical_is_matched_case_insensitively(auth_client, app):
    _add_scan(app, findings=[("Weird finding", "CRITICAL")])

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    series = _series(data)
    assert series["critical"]["total"] == 1
    assert series["vulnerabilities"]["total"] == 1


def test_mountain_axis_is_zero_filled_and_never_runs_into_the_future(auth_client, app):
    _add_scan(app, days_ago=2)

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    assert len(data["dates"]) == 31
    today = datetime.now(timezone.utc).date().isoformat()
    assert all(d <= today for d in data["dates"])
    scans = _series(data)["scans"]["data"]
    assert scans[-3] == 1 and sum(scans) == 1   # the real day, then silence


def test_mountain_respects_the_days_window(auth_client, app):
    """A scan outside the requested window is not plotted, like the other modes."""
    _add_scan(app, days_ago=20)

    data = auth_client.get(f"{TREND}?mode=mountain&days=7&gran=day").get_json()

    # The window itself holds nothing, so it is honestly empty - the same
    # contract as the types/severity views (no stretching old data to fit).
    assert data["empty"] is True and data["dates"] == []

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=day").get_json()

    series = _series(data)
    assert len(data["dates"]) == 31      # the wider window reaches the scan
    assert sum(series["scans"]["data"]) == 1


def test_mountain_week_granularity_keeps_the_axis_aligned(auth_client, app):
    _add_scan(app, days_ago=1)

    data = auth_client.get(f"{TREND}?mode=mountain&days=30&gran=week").get_json()

    assert len(data["dates"]) >= 4
    for s in data["series"]:
        assert len(s["data"]) == len(data["dates"])
    assert sum(_series(data)["scans"]["data"]) == 1
