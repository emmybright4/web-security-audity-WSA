"""WSA route blueprints and registration."""


def register_blueprints(app):
	"""Register all application route blueprints on the Flask app."""
	from .ai import bp as ai_bp
	from .auth import bp as auth_bp
	from .dashboard import bp as dashboard_bp
	from .ip_scan import bp as ip_scan_bp
	from .main import bp as main_bp
	from .reports import bp as reports_bp
	from .scans import bp as scans_bp
	from .settings import bp as settings_bp
	from .targets import bp as targets_bp
	from .templates import bp as templates_bp
	from .tools import bp as tools_bp
	from .vulnerabilities import bp as vulns_bp

	for blueprint in (auth_bp, dashboard_bp, main_bp, scans_bp, vulns_bp,
					  reports_bp, ai_bp, tools_bp, templates_bp, targets_bp,
					  settings_bp, ip_scan_bp):
		app.register_blueprint(blueprint)
