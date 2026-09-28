"""The live chart endpoint: rolling, minute-level buckets from real rows only."""
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Scan, Vulnerability


def _utcnow():
    """Naive UTC - the same shape models.utcnow() is stored as."""
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _add_finding(app, name, minutes_ago=0, days_ago=0, severity="informational"):
    with app.app_context():
        row = Vulnerability(name=name, severity=severity, created_at=(
            _utcnow() - timedelta(minutes=minutes_ago, days=days_ago)))
        db.session.add(row)
        db.session.commit()
        return row.id


def test_live_trend_requires_a_session(app):
    resp = app.test_client().get("/api/dashboard/live-trend")
    assert resp.status_code == 401
    assert resp.is_json and resp.get_json()["error"]


def test_hour_window_is_one_bucket_per_minute_ending_now(auth_client, app):
    _add_finding(app, "Sitemap Present", minutes_ago=3)

    resp = auth_client.get("/api/dashboard/live-trend?window=hour")

    assert resp.status_code == 200, resp.get_data(as_text=True)
    data = resp.get_json()
    assert data["window"] == "hour"
    assert data["bucket_seconds"] == 60
    assert len(data["buckets"]) == 60
    # the newest bucket is the current minute: a finding from seconds ago shows
    stamps = [datetime.fromisoformat(b) for b in data["buckets"]]
    assert stamps == sorted(stamps)
    assert abs((stamps[-1] - datetime.now(timezone.utc)).total_seconds()) < 60
    assert data["empty"] is False and data["events"] == 1
    series = {s["label"]: s for s in data["series"]}
    assert "Sitemap Present" in series
    assert series["Sitemap Present"]["total"] == 1
    assert sum(series["Sitemap Present"]["data"]) == 1


def test_categories_use_the_real_chart_labels(auth_client, app):
    _add_finding(app, "Missing HTTP Strict-Transport-Security header", minutes_ago=1)
    _add_finding(app, "Session cookie missing HttpOnly flag", minutes_ago=1)
    _add_finding(app, "robots.txt was found", minutes_ago=1)

    data = auth_client.get("/api/dashboard/live-trend?window=hour").get_json()

    labels = {s["label"] for s in data["series"]}
    assert "Missing Security Headers" in labels
    assert "Broken Authentication / Sessions" in labels
    assert "Information Disclosure" in labels
    assert data["events"] == 3


def test_findings_outside_the_window_are_not_counted(auth_client, app):
    _add_finding(app, "Sitemap Present", minutes_ago=120)

    data = auth_client.get("/api/dashboard/live-trend?window=hour").get_json()

    assert data["empty"] is True
    assert data["series"] == [] and data["events"] == 0


def test_long_window_keeps_old_findings(auth_client, app):
    _add_finding(app, "Sitemap Present", days_ago=3)

    data = auth_client.get("/api/dashboard/live-trend?window=30d").get_json()

    assert data["window"] == "30d"
    assert data["bucket_seconds"] == 86400
    assert len(data["buckets"]) == 30
    assert data["events"] == 1


def test_unknown_window_falls_back_to_the_hour(auth_client):
    data = auth_client.get("/api/dashboard/live-trend?window=nonsense").get_json()

    assert data["window"] == "hour"
    assert len(data["buckets"]) == 60


def test_only_the_busiest_categories_are_returned(auth_client, app):
    """The legend stays readable: top 6 series, the rest reported as omitted."""
    for i in range(8):
        _add_finding(app, f"Widget finding number {i}", minutes_ago=1)
    _add_finding(app, "Sitemap Present", minutes_ago=1)

    data = auth_client.get("/api/dashboard/live-trend?window=hour").get_json()

    assert len(data["series"]) == 6
    assert data["events"] == 9
    assert data["omitted"] == 3
    totals = [s["total"] for s in data["series"]]
    assert totals == sorted(totals, reverse=True)


def test_scanning_flag_reflects_a_running_scan(auth_client, app):
    with app.app_context():
        scan = Scan(target_url="http://127.0.0.1:8765", scan_type="quick", status="running")
        db.session.add(scan)
        db.session.commit()
        scan_id = scan.id

    assert auth_client.get("/api/dashboard/live-trend").get_json()["scanning"] is True

    with app.app_context():
        db.session.get(Scan, scan_id).status = "completed"
        db.session.commit()

    assert auth_client.get("/api/dashboard/live-trend").get_json()["scanning"] is False


def test_every_bucket_is_returned_even_when_all_are_zero(auth_client):
    """An idle hour still renders a full axis ending at 'now'."""
    data = auth_client.get("/api/dashboard/live-trend?window=day").get_json()

    assert len(data["buckets"]) == 96
    assert data["bucket_seconds"] == 900
    assert data["empty"] is True
