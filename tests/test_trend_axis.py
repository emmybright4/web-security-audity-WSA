"""The trend chart must draw a line across the whole date range.

Regression: the x-axis was built only from dates that held findings, so an
install that scanned on a single day returned one date. Every series then had a
single point - which Chart.js draws as an isolated glowing dot, not a graph.
"""
from datetime import datetime, timedelta, timezone

from app.extensions import db
from app.models import Vulnerability

TREND = "/api/dashboard/vulnerability-trend"


def _add(app, name, days_ago=0, severity="informational"):
    with app.app_context():
        db.session.add(Vulnerability(
            name=name, severity=severity,
            created_at=datetime.now(timezone.utc).replace(tzinfo=None)
            - timedelta(days=days_ago)))
        db.session.commit()


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
