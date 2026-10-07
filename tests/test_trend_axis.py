"""The dashboard's Vulnerability Trend chart keeps the reference look honest.

Regression: the reference graph's dotted Oct-Dec "forecast tail" is projected
data, which this app must never invent (README: "never a fake status"). These
tests pin the data contract the neon chart relies on: the trend endpoint
returns only real buckets - no forecast tail, no series beyond what the DB
holds - so the front end can paint the reference's dark neon style without
ever plotting fabricated values.
"""
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Scan, User, Vulnerability

TREND = "/api/dashboard/vulnerability-trend"


def _add(app, name, days_ago=0, severity="informational"):
    # The data must belong to the signed-in account: findings are reached
    # through their scan, so an unowned row would be invisible to the dashboard.
    with app.app_context():
        owner = User.query.filter_by(email="emmy.bright@wsa.local").first()
        when = (datetime.now(timezone.utc).replace(tzinfo=None)
                - timedelta(days=days_ago))
        scan = Scan(target_url="https://trend.test", scan_type="quick",
                    status="completed", created_at=when, user_id=owner.id)
        db.session.add(scan)
        db.session.flush()
        db.session.add(Vulnerability(
            name=name, severity=severity, scan_id=scan.id, created_at=when))
        db.session.commit()


def _recent_buckets(data, days):
    """Newest `days` buckets - the only range a forecast tail could occupy."""
    return data["dates"][-days:], [s["data"][-days:] for s in data["series"]]


def test_one_day_of_data_still_spans_the_whole_window(auth_client, app):
    """The reported bug: a single day used to collapse the chart to one point."""
    _add(app, "Sitemap Present")

    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=day").get_json()

    assert data["empty"] is False
    assert len(data["dates"]) == 31, "the 30-day window must show every day"
    assert len(data["dates"]) == len(data["series"][0]["data"])
    assert sum(data["series"][0]["data"]) == 1   # the one real finding, on its day


def test_gaps_between_findings_are_zero_filled(auth_client, app):
    _add(app, "Sitemap Present", days_ago=30)      # first bucket of the window
    _add(app, "Missing HTTP Strict-Transport-Security header", days_ago=0)

    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=day").get_json()

    dates = data["dates"]
    assert len(dates) >= 30 and dates[0] < dates[-1]
    series = {s["label"]: s for s in data["series"]}
    sitemap = series["Sitemap Present"]["data"]
    # one finding, 30 days ago: the first bucket, then 30 silent days
    assert sitemap[0] == 1 and sum(sitemap) == 1
    assert all(v == 0 for v in sitemap[1:])
    assert len(sitemap) == len(dates)
    headers = series["Missing Security Headers"]["data"]
    assert headers[-1] == 1 and sum(headers) == 1
    for s in data["series"]:
        assert len(s["data"]) == len(dates), "every series must share the axis"


def test_all_time_view_keeps_a_readable_span(auth_client, app):
    _add(app, "Sitemap Present")

    data = auth_client.get(f"{TREND}?mode=types&days=0&gran=day").get_json()

    assert len(data["dates"]) == 7, "a single day of history still needs an axis"
    assert len(data["series"][0]["data"]) == 7


def test_week_granularity_pads_whole_weeks(auth_client, app):
    _add(app, "Sitemap Present", days_ago=1)

    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=week").get_json()

    assert len(data["dates"]) >= 4
    for s in data["series"]:
        assert len(s["data"]) == len(data["dates"])


def test_severity_mode_is_padded_too(auth_client, app):
    _add(app, "Sitemap Present", severity="high")

    data = auth_client.get(f"{TREND}?mode=severity&days=30&gran=day").get_json()

    assert len(data["dates"]) == 31
    high = next(s for s in data["series"] if s["key"] == "high")
    assert len(high["data"]) == 31 and sum(high["data"]) == 1


def test_still_empty_when_there_are_no_findings(auth_client):
    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=day").get_json()

    assert data["empty"] is True and data["dates"] == []


def test_axis_never_runs_past_today(auth_client, app):
    """Nothing to the right of the newest real bucket is ever plotted."""
    _add(app, "Sitemap Present", days_ago=2)

    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=day").get_json()

    today = datetime.now(timezone.utc).date().isoformat()
    assert all(d <= today for d in data["dates"]), (
        "the endpoint must not invent future buckets for a forecast tail")


def test_series_totals_equal_the_findings_actually_recorded(auth_client, app):
    """A dotted forecast would inflate series totals beyond the real rows."""
    _add(app, "Sitemap Present", days_ago=5)
    _add(app, "Sitemap Present", days_ago=1)
    _add(app, "Missing HTTP Strict-Transport-Security header", days_ago=1)

    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=day").get_json()

    with app.app_context():
        from sqlalchemy import func
        real_total = db.session.query(func.count(Vulnerability.id)).scalar()

    plotted = {s["label"]: sum(s["data"]) for s in data["series"]}
    assert plotted.get("Sitemap Present") == 2
    assert sum(plotted.values()) == real_total


def test_trailing_silence_stays_silent(auth_client, app):
    """The newest buckets of an idle tail are zeros, never extrapolated."""
    _add(app, "Sitemap Present", days_ago=10)

    data = auth_client.get(f"{TREND}?mode=types&days=30&gran=day").get_json()
    _, recent = _recent_buckets(data, 7)

    assert sum(v for series in recent for v in series) == 0, (
        "idle days at the chart's right edge must stay zero, not drift upward")


def test_month_labels_never_invent_future_months(auth_client, app):
    _add(app, "Sitemap Present", days_ago=2)

    data = auth_client.get(f"{TREND}?mode=types&days=0&gran=month").get_json()

    current = datetime.now(timezone.utc).strftime("%Y-%m")
    assert all(d <= current for d in data["dates"])
    for series in data["series"]:
        assert len(series["data"]) == len(data["dates"])
