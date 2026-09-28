"""Regression tests: unauthenticated page visits must reach the login *page*.

Before the fix, ``login_manager.login_view`` pointed at ``auth.login`` — the
POST-only JSON endpoint — so signed-out visitors got a 405 instead of the form.
"""
from urllib.parse import urlparse

import pytest


def test_login_view_points_at_login_page(app):
    from flask import url_for

    with app.test_request_context():
        assert url_for(app.login_manager.login_view) == "/login"


def test_signed_out_dashboard_redirects_to_login_page(client):
    resp = client.get("/")
    assert resp.status_code == 302
    location = resp.headers["Location"]
    path = urlparse(location).path
    assert path == "/login", f"expected /login, got {location!r}"
    # the redirect must NOT go to the JSON API endpoint
    assert not path.startswith("/api/"), f"redirects to JSON API: {location!r}"
    assert "next=%2F" in location  # original destination preserved


def test_signed_out_page_redirect_chain_renders_login_form(client):
    """Full chain: GET / -> /login -> 200 HTML containing the sign-in form."""
    resp = client.get("/", follow_redirects=True)
    assert resp.status_code == 200
    html = resp.get_data(as_text=True)
    assert "loginForm" in html
    assert "Sign in" in html


def test_signed_out_api_stays_json_401(auth_client):
    """API guard must be untouched: JSON 401, not a page redirect."""
    # auth_client is logged in, so use a second, clean client for the signed-out case
    client = auth_client.application.test_client()
    resp = client.get("/api/scans")
    assert resp.status_code == 401
    assert resp.is_json
    assert resp.get_json()["error"]


@pytest.mark.parametrize(
    "page", ["/", "/scan/new", "/templates", "/targets",
             "/vulnerabilities", "/reports", "/ai", "/tools", "/settings"]
)
def test_all_pages_redirect_to_login_page_when_signed_out(client, page):
    resp = client.get(page)
    assert resp.status_code == 302
    assert urlparse(resp.headers["Location"]).path == "/login"
