"""Page-rendering routes (server-rendered Jinja pages)."""
from flask import Blueprint, render_template

bp = Blueprint("main", __name__)

NAV_ITEMS = [
    {"endpoint": "main.dashboard", "icon": "layout-dashboard", "label": "Dashboard"},
    {"endpoint": "main.new_scan", "icon": "radar", "label": "New Scan"},
    {"endpoint": "main.templates", "icon": "layout-template", "label": "Scan Templates"},
    {"endpoint": "main.targets", "icon": "globe", "label": "Target Management"},
    {"endpoint": "main.vulnerabilities", "icon": "bug", "label": "Vulnerabilities"},
    {"endpoint": "main.reports", "icon": "file-text", "label": "Reports"},
    {"endpoint": "main.ai", "icon": "sparkles", "label": "AI Assistant"},
    {"endpoint": "main.tools", "icon": "plug", "label": "Tools & Integrations"},
    {"endpoint": "main.settings", "icon": "settings", "label": "Settings"},
]


@bp.get("/")
def dashboard():
    return render_template("dashboard.html", nav_items=NAV_ITEMS, active="main.dashboard",
                           title="Dashboard")


@bp.get("/scan/new")
def new_scan():
    return render_template("new_scan.html", nav_items=NAV_ITEMS, active="main.new_scan",
                           title="New Scan")


@bp.get("/scans/<int:scan_id>")
def scan_detail(scan_id):
    return render_template("scan_detail.html", nav_items=NAV_ITEMS, active="main.dashboard",
                           title="Scan Results", scan_id=scan_id)


@bp.get("/templates")
def templates():
    return render_template("templates.html", nav_items=NAV_ITEMS, active="main.templates",
                           title="Scan Templates")


@bp.get("/targets")
def targets():
    return render_template("targets.html", nav_items=NAV_ITEMS, active="main.targets",
                           title="Target Management")


@bp.get("/vulnerabilities")
def vulnerabilities():
    return render_template("vulnerabilities.html", nav_items=NAV_ITEMS, active="main.vulnerabilities",
                           title="Vulnerability Findings")


@bp.get("/reports")
def reports():
    return render_template("reports.html", nav_items=NAV_ITEMS, active="main.reports",
                           title="Security Reports")


@bp.get("/ai")
def ai():
    return render_template("ai.html", nav_items=NAV_ITEMS, active="main.ai", title="AI Assistant")


@bp.get("/tools")
def tools():
    return render_template("tools.html", nav_items=NAV_ITEMS, active="main.tools",
                           title="Tools & Integrations")


@bp.get("/settings")
def settings():
    return render_template("settings.html", nav_items=NAV_ITEMS, active="main.settings",
                           title="Settings")
