"""Signing up with a phone number must work on an *upgraded* database.

Regression: ``users.email`` was ``NOT NULL`` before phone sign-up existed, and
``create_all`` never relaxes an existing column. A phone-only account (email is
NULL) therefore failed with an IntegrityError that surfaced as a bare HTTP 500,
even though a fresh database worked. The startup migration rebuilds the table
once; this test proves it does, without losing the rows already stored.
"""
import importlib
import os
import sqlite3

import pytest

# The shape of the users table as it shipped before phone sign-up: email NOT NULL,
# and no unique constraint on phone_number.
LEGACY_USERS_DDL = """
CREATE TABLE users (
    id INTEGER NOT NULL,
    username VARCHAR(80) NOT NULL,
    email VARCHAR(120) NOT NULL,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(40),
    created_at DATETIME NOT NULL,
    phone_number VARCHAR(20),
    email_verified BOOLEAN NOT NULL DEFAULT 0,
    phone_verified BOOLEAN NOT NULL DEFAULT 0,
    primary_auth_method VARCHAR(10) NOT NULL DEFAULT 'email',
    is_active BOOLEAN NOT NULL DEFAULT 1,
    last_login_at DATETIME,
    last_login_ip VARCHAR(64) DEFAULT '',
    updated_at DATETIME,
    PRIMARY KEY (id),
    UNIQUE (username),
    UNIQUE (email)
)
"""


def _legacy_database(path):
    connection = sqlite3.connect(path)
    connection.execute(LEGACY_USERS_DDL)
    connection.execute(
        "INSERT INTO users (id, username, email, password_hash, role, created_at,"
        " email_verified, phone_verified, primary_auth_method, is_active, updated_at)"
        " VALUES (1, 'Old Timer', 'old@wsa.local', '!', 'IT Student',"
        " '2026-01-01 00:00:00', 1, 0, 'email', 1, '2026-01-01 00:00:00')")
    connection.commit()
    connection.close()


@pytest.fixture()
def legacy_app(tmp_path):
    """An app started against a database that predates phone sign-up."""
    db_path = tmp_path / "legacy.db"
    _legacy_database(db_path)

    os.environ["DATABASE_URL"] = f"sqlite:///{db_path.as_posix()}"
    # config caches DATABASE_URL at import time, so reload it after the env is set
    import config
    importlib.reload(config)
    from app import create_app

    app = create_app(config.Config)
    app.config["TESTING"] = True
    app.config["EMAIL_VERIFICATION_ENABLED"] = False
    app.config["LOGIN_OTP_ENABLED"] = False

    from app.services import rate_limit
    rate_limit.reset()
    yield app, db_path
    rate_limit.reset()


def test_phone_signup_works_and_keeps_existing_rows(legacy_app):
    app, db_path = legacy_app
    client = app.test_client()

    resp = client.post("/api/auth/register", json={
        "channel": "phone", "phone_number": "789256647", "country": "RW",
        "username": "fab", "role": "SOC Analyst",
        "password": "secret123", "confirm_password": "secret123"})

    assert resp.status_code == 200, resp.get_data(as_text=True)
    body = resp.get_json()
    assert body["user"]["phone_number"] == "+250789256647"
    assert body["user"]["email"] == ""

    connection = sqlite3.connect(db_path)
    assert connection.execute("select count(*) from users where email='old@wsa.local'"
                              ).fetchone() == (1,), "the migration dropped an account"
    connection.close()


def test_two_phone_only_accounts_do_not_collide_on_a_null_email(legacy_app):
    app, _ = legacy_app
    client = app.test_client()

    first = client.post("/api/auth/register", json={
        "channel": "phone", "phone_number": "789256647", "country": "RW",
        "username": "fab", "role": "SOC Analyst",
        "password": "secret123", "confirm_password": "secret123"})
    client.post("/api/auth/logout")
    second = client.post("/api/auth/register", json={
        "channel": "phone", "phone_number": "788111222", "country": "RW",
        "username": "fab two", "role": "SOC Analyst",
        "password": "secret123", "confirm_password": "secret123"})

    assert first.status_code == 200, first.get_data(as_text=True)
    assert second.status_code == 200, second.get_data(as_text=True)
