"""WSA application factory."""
import logging
import os
import threading

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

    from .routes import register_blueprints
    register_blueprints(app)

    with app.app_context():
        db.create_all()
        _ensure_columns()
        _relax_users_email_nullable()
        _seed_defaults(app)
        _recover_interrupted_ip_scans(app)
        _backfill_verification(app)
        from .routes.settings import apply_db_settings
        apply_db_settings(app)  # DB engine settings win over .env
        # Ensure IP scan tables exist (for upgrades from older DBs)
        from .models import IPScan, IPScanHost, IPScanPort, IPScanVulnerability  # noqa: F401
        db.create_all()

    _start_zap_daemon(app)

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


def _start_zap_daemon(app):
    """Bring up the bundled ZAP daemon in the background (optional engine).

    Runs detached so boot never blocks on the JVM: the Tools page keeps
    reporting the real state either way. Opt out with ZAP_AUTOSTART=false.
    """
    if not app.config.get("ZAP_AUTOSTART", True):
        return

    def _worker():
        from .services.engines import zap_daemon
        zap_daemon.ensure_started(app.config)

    threading.Thread(target=_worker, name="zap-autostart", daemon=True).start()


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


def _recover_interrupted_ip_scans(app):
    """Finish IP scans whose worker died with the previous process.

    A scan only reaches a terminal state while its worker thread is alive. Stop
    the dev server (Ctrl+C) or let the reloader restart it after an edit and the
    row keeps its last status forever: the page then shows a phantom active
    scan, no results and no explanation. Nothing in a fresh process owns those
    rows, so at startup they are closed out here with a message the operator can
    act on.
    """
    from .models import IPScan, utcnow

    stale = IPScan.query.filter(IPScan.status.in_(("pending", "running"))).all()
    for scan in stale:
        scan.status = "failed"
        scan.current_step = "Interrupted"
        scan.error_message = ("The WSA server restarted while this scan was running, "
                              "so it stopped before producing results. Start the scan again.")
        scan.completed_at = utcnow()
    if stale:
        db.session.commit()
        log.info("Marked %d interrupted IP scan(s) as failed.", len(stale))
    return len(stale)


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


# Every column of ``users`` as the model now defines it. Used to rebuild the
# table on an upgraded database (see ``_relax_users_email_nullable``).
_USER_COLUMNS = [
    ("id", "INTEGER NOT NULL"),
    ("username", "VARCHAR(80) NOT NULL"),
    ("email", "VARCHAR(120)"),
    ("phone_number", "VARCHAR(20)"),
    ("password_hash", "VARCHAR(255) NOT NULL"),
    ("role", "VARCHAR(40)"),
    ("email_verified", "BOOLEAN NOT NULL DEFAULT 0"),
    ("phone_verified", "BOOLEAN NOT NULL DEFAULT 0"),
    ("primary_auth_method", "VARCHAR(10) NOT NULL DEFAULT 'email'"),
    ("is_active", "BOOLEAN NOT NULL DEFAULT 1"),
    ("last_login_at", "DATETIME"),
    ("last_login_ip", "VARCHAR(64) DEFAULT ''"),
    ("created_at", "DATETIME NOT NULL"),
    ("updated_at", "DATETIME"),
]


def _relax_users_email_nullable():
    """Let an account be created with a phone number and no email address.

    ``users.email`` was ``NOT NULL`` before phone sign-up existed, and
    ``create_all`` never relaxes an existing column. So on an upgraded database a
    phone-only sign-up failed with an IntegrityError - surfaced as a bare HTTP
    500 - while a fresh database worked. SQLite cannot drop NOT NULL in place, so
    an affected table is rebuilt once, preserving every row.
    """
    from sqlalchemy import inspect, text

    inspector = inspect(db.engine)
    if "users" not in inspector.get_table_names():
        return
    existing = {c["name"]: c for c in inspector.get_columns("users")}
    email = existing.get("email")
    if email is None or email.get("nullable", True):
        return  # already optional - nothing to do

    if db.engine.dialect.name == "sqlite":
        _rebuild_sqlite_users(existing)
    else:
        db.session.execute(text("ALTER TABLE users ALTER COLUMN email DROP NOT NULL"))
        db.session.commit()
    log.info("Relaxed users.email so phone-only accounts can be created.")


def _rebuild_sqlite_users(existing):
    """Recreate ``users`` with a nullable email (SQLite cannot ALTER it).

    Foreign keys are not enforced by this app, so dropping the table does not
    cascade into the child tables that reference it. Only columns that already
    exist are carried over, so this also works for very old databases.
    """
    present = [name for name, _ in _USER_COLUMNS if name in existing]
    column_list = ", ".join(present)
    definitions = ",\n    ".join(
        f"{name} {ddl}" for name, ddl in _USER_COLUMNS if name in existing)

    with db.engine.begin() as connection:
        # A duplicate phone number would make the unique index below fail and
        # block startup; detect it first and leave the constraint out in that case.
        duplicates = connection.exec_driver_sql(
            "SELECT COUNT(*) FROM (SELECT phone_number FROM users "
            "WHERE phone_number IS NOT NULL GROUP BY phone_number "
            "HAVING COUNT(*) > 1)").scalar()
        constraints = ["PRIMARY KEY (id)", "UNIQUE (username)", "UNIQUE (email)"]
        if not duplicates:
            constraints.append("UNIQUE (phone_number)")
        connection.exec_driver_sql(
            f"CREATE TABLE users_migrated (\n    {definitions},\n    "
            + ",\n    ".join(constraints) + "\n)")
        connection.exec_driver_sql(
            f"INSERT INTO users_migrated ({column_list}) SELECT {column_list} FROM users")
        connection.exec_driver_sql("DROP TABLE users")
        connection.exec_driver_sql("ALTER TABLE users_migrated RENAME TO users")
