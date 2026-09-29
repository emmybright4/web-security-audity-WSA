"""WSA application factory."""
import logging
import os

from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from .extensions import db, login_manager, migrate, socketio

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(name)s: %(message)s")
log = logging.getLogger("wsa")


def create_app(config_class=Config):
    app = Flask(__name__)
    app.config.from_object(config_class)
    CORS(app)

    os.makedirs(app.config["REPORTS_DIR"], exist_ok=True)

    db.init_app(app)
    migrate.init_app(app, db)
    socketio.init_app(app)
    login_manager.init_app(app)

    from . import models  # noqa: F401  (register models with SQLAlchemy)
    from .events import register_socketio_events
    register_socketio_events(socketio)

    from .routes.auth import bp as auth_bp
    from .routes.dashboard import bp as dashboard_bp
    from .routes.main import bp as main_bp
    from .routes.scans import bp as scans_bp
    from .routes.vulnerabilities import bp as vulns_bp
    from .routes.reports import bp as reports_bp
    from .routes.ai import bp as ai_bp
    from .routes.tools import bp as tools_bp
    from .routes.templates import bp as templates_bp
    from .routes.targets import bp as targets_bp
    from .routes.settings import bp as settings_bp
    from .routes.ip_scan import bp as ip_scan_bp
    for bp in (auth_bp, dashboard_bp, main_bp, scans_bp, vulns_bp, reports_bp,
               ai_bp, tools_bp, templates_bp, targets_bp, settings_bp, ip_scan_bp):
        app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        _ensure_columns()
        _seed_defaults(app)
        _backfill_verification(app)
        from .routes.settings import apply_db_settings
        apply_db_settings(app)  # DB engine settings win over .env
        # Ensure IP scan tables exist (for upgrades from older DBs)
        from .models import IPScan, IPScanHost, IPScanPort, IPScanVulnerability  # noqa: F401
        db.create_all()

    @app.errorhandler(404)
    def not_found(_e):
        if _wants_json():
            return jsonify(error="Not found"), 404
        from flask import render_template
        return render_template("errors/404.html"), 404

    @app.errorhandler(500)
    def server_error(e):
        log.exception("Unhandled server error: %s", e)
        if _wants_json():
            return jsonify(error="Internal server error"), 500
        from flask import render_template
        return render_template("errors/500.html"), 500

    @app.context_processor
    def _inject_user():
        from flask_login import current_user
        row = getattr(current_user, "row", None)
        initials = name = email = role = ""
        if row is not None:
            name = row.username or ""
            email = row.email or ""
            role = row.role or ""
            parts = name.split()[:2]
            initials = "".join(p[0] for p in parts).upper() or name[:2].upper()
        return dict(user_initials=initials, user_name=name,
                    user_email=email, user_role=role)

    def _wants_json():
        from flask import request
        return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"

    log.info("WSA application ready.")
    return app


def _seed_defaults(app):
    """Create default user + tool rows on first run."""
    from .models import ToolIntegration, User

    if not User.query.filter_by(username="Emmy Bright").first():
        u = User(username="Emmy Bright", email="emmy.bright@wsa.local",
                 password_hash="!", role="IT Student", email_verified=True,
                 primary_auth_method="email")
        u.set_password("wsa-admin-2026")
        db.session.add(u)
    for name in ("OWASP ZAP", "ZAP-MCP", "Playwright", "Nuclei", "gosqli", "AI / LLM"):
        if not ToolIntegration.query.filter_by(name=name).first():
            db.session.add(ToolIntegration(name=name, status="not_configured"))
    db.session.commit()


def _backfill_verification(app):
    """Trust accounts that predate email verification - never anyone else.

    Accounts created before verification existed were vetted by the operator, and
    forcing an OTP would lock every existing install out. The condition is
    self-describing: a database that has never issued a single verification code
    is one that predates the feature. Once a code exists, no account can ever be
    auto-verified again, so an account that simply did not finish verifying stays
    unverified (and can ask for a new code at sign-in) instead of being blessed by
    a server restart.
    """
    from .models import User, VerificationCode, utcnow

    trusting_legacy = VerificationCode.query.first() is None
    trusted = 0
    changed = False
    for user in User.query.all():
        if trusting_legacy and user.email and not user.email_verified:
            user.email_verified = True
            trusted += 1
            changed = True
        if not user.primary_auth_method:
            user.primary_auth_method = "email"
            changed = True
        if user.updated_at is None:
            user.updated_at = user.created_at or utcnow()
            changed = True
    if changed:
        db.session.commit()
    if trusted:
        log.info("Trusted %d account(s) created before email verification existed.", trusted)


# Columns added after a table was first created. ``create_all`` only creates
# missing *tables*, so an existing database needs these to be added in place.
_ADDED_COLUMNS = {
    "users": [
        ("phone_number", "VARCHAR(20)"),
        ("email_verified", "BOOLEAN NOT NULL DEFAULT 0"),
        ("phone_verified", "BOOLEAN NOT NULL DEFAULT 0"),
        ("primary_auth_method", "VARCHAR(10) NOT NULL DEFAULT 'email'"),
        ("is_active", "BOOLEAN NOT NULL DEFAULT 1"),
        ("last_login_at", "DATETIME"),
        ("last_login_ip", "VARCHAR(64) DEFAULT ''"),
        ("updated_at", "DATETIME"),
    ],
    "scans": [("user_id", "INTEGER")],
    "ip_scans": [("user_id", "INTEGER")],
}


def _ensure_columns():
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    existing_tables = set(inspector.get_table_names())
    for table, columns in _ADDED_COLUMNS.items():
        if table not in existing_tables:
            continue  # create_all already made it with the full definition
        present = {c["name"] for c in inspector.get_columns(table)}
        for name, ddl in columns:
            if name in present:
                continue
            db.session.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
            log.info("Added missing column %s.%s", table, name)
    db.session.commit()
