"""Dashboard API: live statistics from the database. No hardcoded values."""
from collections import defaultdict
from datetime import date, timedelta

from flask import Blueprint, jsonify, request
from sqlalchemy import func

from ..extensions import db
from ..models import Scan, Vulnerability

bp = Blueprint("dashboard", __name__, url_prefix="/api/dashboard")

SEV_GROUPS = {
    "high": ("high", "critical"),
    "medium": ("medium",),
    "low": ("low",),
    "informational": ("informational", "info"),
}

# Severity buckets kept separate (critical is NOT merged into high here).
SEV_BUCKETS = {
    "critical": "critical",
    "high": "high",
    "medium": "medium",
    "low": "low",
    "info": "informational",
    "informational": "informational",
}
SEV_ORDER = ("critical", "high", "medium", "low", "informational")
SEV_LABELS = {
    "critical": "Critical",
    "high": "High",
    "medium": "Medium",
    "low": "Low",
    "informational": "Informational",
}

# Keyword buckets for real finding names found in the database. Any finding
# that matches no rule keeps its own name as the vulnerability type, so the
# trend chart is always driven by what actually exists in the DB.
TYPE_BUCKETS = [
    ("sql_injection", "SQL Injection",
     ("sql", "sql injection", "blind injection")),
    ("xss", "Cross-Site Scripting (XSS)",
     ("xss", "cross-site scripting", "script injection")),
    ("missing_headers", "Missing Security Headers",
     ("header", "csp", "content-security-policy", "hsts", "strict-transport",
      "x-frame", "clickjacking", "referrer-policy", "permissions-policy",
      "x-content-type")),
    ("auth_sessions", "Broken Authentication / Sessions",
     ("cookie", "session", "auth", "password", "login", "brute", "csrf")),
    ("ssl_tls", "SSL/TLS Issues",
     ("tls", "ssl", "certificate", "cipher", "https")),
    ("misconfig", "Security Misconfiguration",
     ("exposed", "backup", ".env", "git", "phpinfo", "listing", "misconfig",
      "debug", "config", "directory")),
    ("info_disclosure", "Information Disclosure",
     ("robots", "disclosure", "comment", "stack trace", "error message")),
]

MAX_TYPES = 10          # top N vulnerability types on the chart...
MAX_DATES = 90          # ...and max distinct dates returned
GRANS = ("day", "week", "month")


def _gran_key(d_str, gran):
    """Collapse a YYYY-MM-DD date into its day/week/month bucket label."""
    if gran == "week":
        d = date.fromisoformat(d_str)
        start = d - timedelta(days=d.weekday())          # Monday of that week
        return start.isoformat()
    if gran == "month":
        return d_str[:7]                                  # YYYY-MM
    return d_str


def _type_bucket(name):
    """Map a real finding name to a chart-friendly type label."""
    n = (name or "").lower()
    for key, label, needles in TYPE_BUCKETS:
        if any(needle in n for needle in needles):
            return key, label
    clean = (name or "").strip() or "Other"
    return "type:" + clean, clean


def _grouped_counts(query_filter=None):
    q = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
    if query_filter is not None:
        q = q.filter(query_filter)
    rows = q.group_by(Vulnerability.severity).all()
    raw = dict(rows)
    out = {}
    for group, members in SEV_GROUPS.items():
        out[group] = sum(raw.get(m, 0) for m in members)
    return out


def _severity_counts(query_filter=None):
    """Per-severity counts with critical reported separately."""
    q = db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
    if query_filter is not None:
        q = q.filter(query_filter)
    raw = dict(q.group_by(Vulnerability.severity).all())
    return {
        "critical": raw.get("critical", 0),
        "high": raw.get("high", 0),
        "medium": raw.get("medium", 0),
        "low": raw.get("low", 0),
        "informational": raw.get("informational", 0) + raw.get("info", 0),
    }


@bp.get("/summary")
def summary():
    """Live totals + comparison with the previous equivalent period."""
    try:
        total_scans = db.session.query(func.count(Scan.id)).filter(
            Scan.status.in_(["completed", "failed", "cancelled"])).scalar() or 0
        total_scans_all = db.session.query(func.count(Scan.id)).scalar() or 0
        counts = _grouped_counts()
        total_findings = sum(counts.values())

        # previous-period comparison (period = span between first and last scan,
        # or last 7 days when history is too short)
        trend = {"total_scans": None, "high": None, "medium": None, "low": None}
        first = db.session.query(func.min(Scan.created_at)).scalar()
        last = db.session.query(func.max(Scan.created_at)).scalar()
        if first and last and first < last:
            span = (last - first) / 2
            mid = first + span
            old_scans = db.session.query(func.count(Scan.id)).filter(
                Scan.created_at < mid).scalar() or 0
            new_scans = total_scans_all - old_scans
            trend["total_scans"] = _pct(old_scans, new_scans)

            old_counts = _grouped_counts(Vulnerability.created_at < mid)
            new_counts_total = total_findings - sum(old_counts.values())
            for g in ("high", "medium", "low"):
                trend[g] = _pct(old_counts[g], counts[g] - old_counts[g])

        spark = _sparklines()
        return jsonify(
            total_scans=total_scans,
            total_scans_all=total_scans_all,
            high_risk=counts["high"],
            medium_risk=counts["medium"],
            low_risk=counts["low"],
            informational=counts["informational"],
            total_findings=total_findings,
            trend=trend,
            sparklines=spark,
            generated_at=db.session.query(func.max(Scan.completed_at)).scalar(),
            empty=total_scans_all == 0 and total_findings == 0,
            message=("No scans performed yet. Start your first authorized audit."
                     if total_scans_all == 0 and total_findings == 0 else None),
        )
    except Exception as exc:
        return jsonify(error=f"Failed to compute dashboard summary: {exc}"), 500


@bp.get("/findings-overview")
def findings_overview():
    """Live severity distribution (critical kept separate from high)."""
    try:
        counts = _severity_counts()
        total = sum(counts.values())
        return jsonify(counts=counts, total=total, empty=total == 0)
    except Exception as exc:
        return jsonify(error=f"Failed to compute findings overview: {exc}"), 500


@bp.get("/vulnerability-trend")
def vulnerability_trend():
    """Findings per day, grouped by real vulnerability types or by severity.

    Query params:
      mode=types|severity  (default types)
      days=7|14|30|90|0    (0 = all time)
    """
    try:
        mode = (request.args.get("mode") or "types").lower()
        if mode not in ("types", "severity"):
            mode = "types"
        days = request.args.get("days", type=int) or 0
        gran = (request.args.get("gran") or "day").lower()
        if gran not in GRANS:
            gran = "day"

        # X-axis = scan dates (fall back to the finding's own date when the
        # scan row is missing). Only real rows are aggregated.
        date_col = func.coalesce(func.date(Scan.created_at),
                                 func.date(Vulnerability.created_at))
        q = (db.session.query(date_col, Vulnerability.name, Vulnerability.severity)
             .outerjoin(Scan, Scan.id == Vulnerability.scan_id))
        if days > 0:
            q = q.filter(Vulnerability.created_at >= func.date("now", f"-{days} day"))
        rows = q.all()

        if not rows or not any(r[0] for r in rows):
            return jsonify(mode=mode, days=days, gran=gran, dates=[], series=[],
                           totals={}, empty=True)

        # Collapse raw dates into day/week/month buckets before anything else.
        bucketed = defaultdict(list)
        for d, name, sev in rows:
            if d:
                bucketed[_gran_key(str(d), gran)].append((name, sev))
        dates = sorted(bucketed)
        if len(dates) > MAX_DATES:
            dates = dates[-MAX_DATES:]
            keep = set(dates)
            bucketed = {k: v for k, v in bucketed.items() if k in keep}

        by_date = defaultdict(lambda: defaultdict(int))
        totals = defaultdict(int)
        labels = {}
        for d in dates:
            for name, sev in bucketed[d]:
                if mode == "severity":
                    key = SEV_BUCKETS.get((sev or "").lower(), "informational")
                    label = SEV_LABELS[key]
                else:
                    key, label = _type_bucket(name)
                by_date[d][key] += 1
                totals[key] += 1
                labels[key] = label

        # Keep the chart readable: top N types, remainder merged into "Other".
        if mode == "types" and len(totals) > MAX_TYPES:
            top = [k for k, _ in
                   sorted(totals.items(), key=lambda kv: kv[1], reverse=True)[:MAX_TYPES]]
            top_set = set(top)
            other_key = "other"
            other_total = sum(v for k, v in totals.items() if k not in top_set)
            merged = defaultdict(lambda: defaultdict(int))
            for d, kv in by_date.items():
                for k, v in kv.items():
                    merged[d][k if k in top_set else other_key] += v
            by_date = merged
            labels = {k: labels[k] for k in top}
            labels[other_key] = "Other"
            totals = defaultdict(int, {**{k: totals[k] for k in top},
                                       other_key: other_total})

        if mode == "severity":
            order = [k for k in SEV_ORDER if k in totals]
        else:
            order = [k for k, _ in
                     sorted(totals.items(), key=lambda kv: kv[1], reverse=True)]

        series = [{
            "key": k,
            "label": labels.get(k, k),
            "total": totals[k],
            "data": [by_date[d].get(k, 0) for d in dates],
        } for k in order]

        return jsonify(mode=mode, days=days, gran=gran, dates=dates, series=series,
                       totals={k: totals[k] for k in order}, empty=False)
    except Exception as exc:
        return jsonify(error=f"Failed to compute trend: {exc}"), 500


@bp.get("/sparklines")
def sparklines_endpoint():
    try:
        return jsonify(sparklines=_sparklines())
    except Exception as exc:
        return jsonify(error=str(exc)), 500


def _sparklines():
    """Per-day finding counts for the last 14 days for mini charts."""
    rows = (db.session.query(func.date(Vulnerability.created_at), Vulnerability.severity,
                             func.count(Vulnerability.id))
            .filter(Vulnerability.created_at >= func.date("now", "-14 day"))
            .group_by(func.date(Vulnerability.created_at), Vulnerability.severity).all())
    by_day = defaultdict(lambda: {"high": 0, "medium": 0, "low": 0, "informational": 0})
    for d, sev, cnt in rows:
        if not d:
            continue
        g = ("high" if sev in ("high", "critical") else "medium" if sev == "medium"
             else "low" if sev == "low" else "informational")
        by_day[str(d)][g] += cnt
    return {d: c for d, c in by_day.items()}


def _pct(old, new):
    """Percentage change old -> new; None when undefined."""
    if old == 0:
        return None if new == 0 else 100.0
    return round(100.0 * (new - old) / old, 1)
