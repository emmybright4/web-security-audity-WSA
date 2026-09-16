"""WSA application factory."""
import logging
import os

from flask import Flask, jsonify
from flask_cors import CORS

from config import Config
from .extensions import db, migrate, socketio

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

    from . import models  # noqa: F401  (register models with SQLAlchemy)
    from .events import register_socketio_events
    register_socketio_events(socketio)

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
    for bp in (dashboard_bp, main_bp, scans_bp, vulns_bp, reports_bp,
               ai_bp, tools_bp, templates_bp, targets_bp, settings_bp):
        app.register_blueprint(bp)

    with app.app_context():
        db.create_all()
        _seed_defaults(app)

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

    def _wants_json():
        from flask import request
        return request.path.startswith("/api/") or request.accept_mimetypes.best == "application/json"

    log.info("WSA application ready.")
    return app


def _seed_defaults(app):
    """Create default user + tool rows on first run."""
    from .models import ToolIntegration, User

    if not User.query.filter_by(username="Emmy Bright").first():
        db.session.add(User(username="Emmy Bright", email="emmy.bright@wsa.local",
                            password_hash="!", role="IT Student"))
    for name in ("OWASP ZAP", "ZAP-MCP", "Playwright", "Nuclei", "gosqli", "AI / LLM"):
        if not ToolIntegration.query.filter_by(name=name).first():
            db.session.add(ToolIntegration(name=name, status="not_configured"))
    db.session.commit()
