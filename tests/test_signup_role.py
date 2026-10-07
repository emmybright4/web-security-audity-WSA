"""Signing up requires a role, and "Other" keeps the typed description."""


def test_signup_requires_a_role(app, client):
    resp = client.post("/api/auth/register", json={
        "channel": "email", "email": "norole@example.com",
        "password": "secret123", "confirm_password": "secret123"})

    assert resp.status_code == 400
    assert "role" in resp.get_json()["error"].lower()


def test_other_role_stores_the_description(app, client, otp_box):
    resp = client.post("/api/auth/register", json={
        "channel": "email", "email": "other@example.com",
        "role": "Other", "role_other": "Compliance Officer",
        "password": "secret123", "confirm_password": "secret123"})

    assert resp.status_code == 201, resp.get_data(as_text=True)
    from app.models import User
    with app.app_context():
        user = User.query.filter_by(email="other@example.com").first()
        assert user is not None
        assert user.role == "Compliance Officer"


def test_known_role_is_stored_as_chosen(app, client, otp_box):
    resp = client.post("/api/auth/register", json={
        "channel": "email", "email": "soc@example.com",
        "role": "SOC Analyst",
        "password": "secret123", "confirm_password": "secret123"})

    assert resp.status_code == 201, resp.get_data(as_text=True)
    from app.models import User
    with app.app_context():
        assert User.query.filter_by(email="soc@example.com").first().role == "SOC Analyst"
