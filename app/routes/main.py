"""Page-rendering routes (server-rendered Jinja pages)."""
from functools import wraps

from flask import Blueprint, redirect, render_template, request, url_for
from flask_login import current_user, login_required

bp = Blueprint("main", __name__)

NAV_ITEMS = [
    {"endpoint": "main.dashboard", "icon": "layout-dashboard", "label": "Dashboard"},
    {"endpoint": "main.new_scan", "icon": "radar", "label": "New Scan"},
    {"endpoint": "main.ip_scanning", "icon": "pc-display-horizontal", "label": "IP Scanning"},
    {"endpoint": "main.templates", "icon": "layout-template", "label": "Scan Templates"},
    {"endpoint": "main.targets", "icon": "globe", "label": "Target Management"},
    {"endpoint": "main.vulnerabilities", "icon": "bug", "label": "Vulnerabilities"},
    {"endpoint": "main.reports", "icon": "file-text", "label": "Reports"},
    {"endpoint": "main.ai", "icon": "sparkles", "label": "AI Assistant"},
    {"endpoint": "main.tools", "icon": "plug", "label": "Tools & Integrations"},
    {"endpoint": "main.settings", "icon": "settings", "label": "Settings"},
]


@bp.get("/")
@login_required
def dashboard():
    return render_template("dashboard.html", nav_items=NAV_ITEMS, active="main.dashboard",
                           title="Dashboard")


@bp.get("/scan/new")
@login_required
def new_scan():
    return render_template("new_scan.html", nav_items=NAV_ITEMS, active="main.new_scan",
                           title="New Scan")


@bp.get("/ip-scanning")
@login_required
def ip_scanning():
    return render_template("ip_scanning.html", nav_items=NAV_ITEMS,
                           active="main.ip_scanning", title="IP Scanning")


@bp.get("/scans/<int:scan_id>")
@login_required
def scan_detail(scan_id):
    return render_template("scan_detail.html", nav_items=NAV_ITEMS, active="main.dashboard",
                           title="Scan Results", scan_id=scan_id)


@bp.get("/templates")
@login_required
def templates():
    return render_template("templates.html", nav_items=NAV_ITEMS, active="main.templates",
                           title="Scan Templates")


@bp.get("/targets")
@login_required
def targets():
    return render_template("targets.html", nav_items=NAV_ITEMS, active="main.targets",
                           title="Target Management")


@bp.get("/vulnerabilities")
@login_required
def vulnerabilities():
    return render_template("vulnerabilities.html", nav_items=NAV_ITEMS, active="main.vulnerabilities",
                           title="Vulnerability Findings")


@bp.get("/reports")
@login_required
def reports():
    return render_template("reports.html", nav_items=NAV_ITEMS, active="main.reports",
                           title="Security Reports")


@bp.get("/ai")
@login_required
def ai():
    return render_template("ai.html", nav_items=NAV_ITEMS, active="main.ai", title="AI Assistant")


@bp.get("/tools")
@login_required
def tools():
    return render_template("tools.html", nav_items=NAV_ITEMS, active="main.tools",
                           title="Tools & Integrations")


@bp.get("/settings")
@login_required
def settings():
    return render_template("settings.html", nav_items=NAV_ITEMS, active="main.settings",
                           title="Settings")
