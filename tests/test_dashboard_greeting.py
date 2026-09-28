"""The dashboard must greet whoever is signed in, not a hardcoded name.

Before the fix the heading was the literal text ``Welcome back, Emmy Bright``,
so every other account saw someone else's name.
"""
from .conftest import register_and_verify


def _register(client, otp_box, username, email):
    return register_and_verify(client, otp_box, username=username, email=email)


def test_dashboard_greets_the_signed_in_user(app, client, otp_box):
    _register(client, otp_box, "Niyodusenga Emmanuel", "ne@wsa.local")

    html = client.get("/").get_data(as_text=True)

    assert "Niyodusenga Emmanuel" in html, "the signed-in user's name must be shown"
    assert "Emmy Bright" not in html, "the seeded account's name leaked into the page"


def test_greeting_changes_between_accounts(app, client, otp_box):
    """Two different accounts must not render the same heading."""
    _register(client, otp_box, "Grace Mutesi", "grace@wsa.local")
    first = client.get("/").get_data(as_text=True)
    client.post("/api/auth/logout")

    _register(client, otp_box, "Alice Kamanzi", "alice@wsa.local")
    second = client.get("/").get_data(as_text=True)

    assert "Grace Mutesi" in first and "Grace Mutesi" not in second
    assert "Alice Kamanzi" in second
