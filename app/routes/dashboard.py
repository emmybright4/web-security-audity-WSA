"""Dashboard API: live statistics from the database. No hardcoded values."""
from collections import defaultdict
from datetime import date, datetime, timedelta, timezone

from flask import Blueprint, jsonify, request
from sqlalchemy import and_, func

from ..extensions import db
from ..models import Scan, Vulnerability
from ._api_guard import api_login_required
from ._scope import user_id

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
     ("xss", "cross-site scripting", "script injection", "reflected",
      "stored xss", "dom-based")),
    ("mitm", "Man-in-the-Middle",
     ("man-in-the-middle", "mitm", "mitm attack", "ssl stripping",
      "downgrade attack", "intercept", "ssl/tls interception",
      "ssl stripping attack", "insecure transport")),
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

# The main dashboard chart (mode=mountain) always plots exactly these three
# series, in this order. Fixed keys let the front end pin the neon colours.
MOUNTAIN_KEYS = ("vulnerabilities", "scans", "critical")

# The delta shown next to each stat card compares the most recent N days with
# the N days immediately before them.
TREND_WINDOW_DAYS = 7


def _mountain_trend(days, gran):
    """Real security analytics for the main dashboard chart.

    Exactly three series, every point a real row:
      - Security Scans: scan rows created in the bucket
      - Vulnerabilities Found: findings recorded in the bucket
      - Critical Findings: critical-severity findings in the bucket

    Nothing is projected or interpolated: an idle day is a zero, and an
    account that has never scanned gets empty=True so the UI can show its
    start-at-zero state. Days with scans but zero findings still render -
    that is exactly what the account's history looks like.
    """
    if gran not in GRANS:
        gran = "day"

    # Findings are bucketed by their scan's date (falling back to the finding's
    # own date when the scan row is missing), matching the types/severity view.
    f_date = func.coalesce(func.date(Scan.created_at),
                           func.date(Vulnerability.created_at))
    fq = (db.session.query(f_date, Vulnerability.severity)
          .outerjoin(Scan, Scan.id == Vulnerability.scan_id)
          .filter(Scan.user_id == user_id()))
    sq = db.session.query(func.date(Scan.created_at)).filter(
        Scan.user_id == user_id())
    if days > 0:
        fq = fq.filter(Vulnerability.created_at >= func.date("now", f"-{days} day"))
        sq = sq.filter(Scan.created_at >= func.date("now", f"-{days} day"))
    f_rows = fq.all()
    scan_days = {str(r[0]) for r in sq.all() if r[0]}

    present = sorted({str(r[0]) for r in f_rows if r[0]} | scan_days)
    if not present:
        return jsonify(mode="mountain", days=days, gran=gran, dates=[], series=[],
                       totals={}, empty=True)

    # Same zero-filled axis as the other modes: the whole requested span
    # exists even where nothing happened, so the curves stay continuous.
    today = datetime.now(timezone.utc).date()   # rows are UTC; SQLite date('now') is UTC
    if days > 0:
        start, end = today - timedelta(days=days), today
    else:
        start = date.fromisoformat(present[0][:10])
        end = max(date.fromisoformat(present[-1][:10]), today)
        if (end - start).days < 6:              # keep the all-time view readable
            start = end - timedelta(days=6)
    span = [start + timedelta(days=i) for i in range((end - start).days + 1)]
    dates = sorted({_gran_key(d.isoformat(), gran) for d in span})
    if len(dates) > MAX_DATES:
        dates = dates[-MAX_DATES:]
    keep = set(dates)

    findings = defaultdict(lambda: {"total": 0, "critical": 0})
    scans = defaultdict(int)
    for d, sev in f_rows:
        if not d:
            continue
        k = _gran_key(str(d), gran)
        if k in keep:
            findings[k]["total"] += 1
            if (sev or "").lower() == "critical":
                findings[k]["critical"] += 1
    for d in scan_days:
        k = _gran_key(d, gran)
        if k in keep:
            scans[k] += 1

    series = [{
        "key": key,
        "label": {
            "vulnerabilities": "Vulnerabilities Found",
            "scans": "Security Scans",
            "critical": "Critical Findings",
        }[key],
        "total": {
            "vulnerabilities": sum(v["total"] for v in findings.values()),
            "scans": sum(scans.values()),
            "critical": sum(v["critical"] for v in findings.values()),
        }[key],
        "data": {
            "vulnerabilities": [findings[d]["total"] for d in dates],
            "scans": [scans[d] for d in dates],
            "critical": [findings[d]["critical"] for d in dates],
        }[key],
    } for key in MOUNTAIN_KEYS]

    return jsonify(mode="mountain", days=days, gran=gran, dates=dates,
                   series=series, totals={s["key"]: s["total"] for s in series},
                   empty=False)


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
    # Scoped to the signed-in account: findings are reached through their scan,
    # so a new user's dashboard starts at zero and never counts anyone else's.
    q = (db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
         .join(Scan, Vulnerability.scan_id == Scan.id)
         .filter(Scan.user_id == user_id()))
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
    q = (db.session.query(Vulnerability.severity, func.count(Vulnerability.id))
         .join(Scan, Vulnerability.scan_id == Scan.id)
         .filter(Scan.user_id == user_id()))
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
@api_login_required
def summary():
    """Live totals + comparison with the previous equivalent period."""
    try:
        total_scans = db.session.query(func.count(Scan.id)).filter(
            Scan.user_id == user_id(),
            Scan.status.in_(["completed", "failed", "cancelled"])).scalar() or 0
        total_scans_all = db.session.query(func.count(Scan.id)).filter(
            Scan.user_id == user_id()).scalar() or 0
        counts = _grouped_counts()
        total_findings = sum(counts.values())

        # Period-over-period comparison: the most recent TREND_WINDOW_DAYS days
        # against the TREND_WINDOW_DAYS days immediately before them. (Splitting
        # the whole history at its mid point produced figures like "+1700%".)
        trend = {"total_scans": None, "high": None, "medium": None, "low": None}
        newest = db.session.query(func.max(Scan.created_at)).filter(
            Scan.user_id == user_id()).scalar()
        if newest:
            recent_start = newest - timedelta(days=TREND_WINDOW_DAYS)
            previous_start = recent_start - timedelta(days=TREND_WINDOW_DAYS)

            recent_scans = db.session.query(func.count(Scan.id)).filter(
                Scan.user_id == user_id(),
                Scan.created_at >= recent_start).scalar() or 0
            previous_scans = db.session.query(func.count(Scan.id)).filter(
                Scan.user_id == user_id(),
                and_(Scan.created_at >= previous_start,
                     Scan.created_at < recent_start)).scalar() or 0
            trend["total_scans"] = _pct(previous_scans, recent_scans)

            recent_counts = _grouped_counts(Vulnerability.created_at >= recent_start)
            previous_counts = _grouped_counts(
                and_(Vulnerability.created_at >= previous_start,
                     Vulnerability.created_at < recent_start))
            for g in ("high", "medium", "low"):
                trend[g] = _pct(previous_counts[g], recent_counts[g])

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
            generated_at=db.session.query(func.max(Scan.completed_at)).filter(
                Scan.user_id == user_id()).scalar(),
            empty=total_scans_all == 0 and total_findings == 0,
            message=("No scans performed yet. Start your first authorized audit."
                     if total_scans_all == 0 and total_findings == 0 else None),
        )
    except Exception as exc:
        return jsonify(error=f"Failed to compute dashboard summary: {exc}"), 500


@bp.get("/findings-overview")
@api_login_required
def findings_overview():
    """Live severity distribution (critical kept separate from high)."""
    try:
        counts = _severity_counts()
        total = sum(counts.values())
        return jsonify(counts=counts, total=total, empty=total == 0)
    except Exception as exc:
        return jsonify(error=f"Failed to compute findings overview: {exc}"), 500


@bp.get("/vulnerability-trend")
@api_login_required
def vulnerability_trend():
    """Findings per day, grouped by real vulnerability types or by severity.

    Query params:
      mode=types|severity|mountain  (default types; mountain = the main
        dashboard chart's fixed three-series security analytics view)
      days=7|14|30|90|0    (0 = all time)
    """
    try:
        mode = (request.args.get("mode") or "types").lower()
        if mode not in ("types", "severity", "mountain"):
            mode = "types"
        if mode == "mountain":
            return _mountain_trend(days=request.args.get("days", type=int) or 0,
                                   gran=(request.args.get("gran") or "day").lower())
        days = request.args.get("days", type=int) or 0
        gran = (request.args.get("gran") or "day").lower()
        if gran not in GRANS:
            gran = "day"

        # X-axis = scan dates (fall back to the finding's own date when the
        # scan row is missing). Only real rows are aggregated.
        date_col = func.coalesce(func.date(Scan.created_at),
                                 func.date(Vulnerability.created_at))
        q = (db.session.query(date_col, Vulnerability.name, Vulnerability.severity)
             .outerjoin(Scan, Scan.id == Vulnerability.scan_id)
             .filter(Scan.user_id == user_id()))
        if days > 0:
            q = q.filter(Vulnerability.created_at >= func.date("now", f"-{days} day"))
        rows = q.all()

        if not rows or not any(r[0] for r in rows):
            return jsonify(mode=mode, days=days, gran=gran, dates=[], series=[],
                           totals={}, empty=True)

        # Collapse raw rows into day/week/month buckets.
        bucketed = defaultdict(list)
        for d, name, sev in rows:
            if d:
                bucketed[_gran_key(str(d), gran)].append((name, sev))

        # The axis spans the *whole* requested range, including the days that
        # hold no findings. Without this, an install that scanned only today
        # returned a single date: every series became one lone point, which
        # Chart.js renders as isolated dots rather than a line. The zero-filled
        # gaps are honest - "no findings that day" is exactly what happened.
        present = sorted({str(r[0]) for r in rows if r[0]})
        today = datetime.now(timezone.utc).date()   # rows are UTC; SQLite date('now') is UTC
        if days > 0:
            start, end = today - timedelta(days=days), today   # same bound as the filter
        else:
            start = date.fromisoformat(present[0][:10])
            end = max(date.fromisoformat(present[-1][:10]), today)
            if (end - start).days < 6:              # keep the all-time view readable
                start = end - timedelta(days=6)
        span = [start + timedelta(days=i) for i in range((end - start).days + 1)]
        dates = sorted({_gran_key(d.isoformat(), gran) for d in span})
        if len(dates) > MAX_DATES:
            dates = dates[-MAX_DATES:]
        keep = set(dates)
        bucketed = {k: v for k, v in bucketed.items() if k in keep}
        for d in dates:
            bucketed.setdefault(d, [])              # every bucket exists, most are zero

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


# ------------------------------------------------------------- live findings ----
# Rolling window for the dashboard's live chart. Minute buckets make a running
# scan visibly move the line; the longer windows give the same panel a wide view.
LIVE_WINDOWS = {
    # window: (bucket seconds, number of buckets)
    "hour": (60, 60),           # last 60 minutes -> one point per minute
    "day": (900, 96),           # last 24 hours   -> one point per 15 minutes
    "30d": (86400, 30),         # last 30 days    -> one point per day
}
LIVE_MAX_SERIES = 6             # keep the live panel readable


def _bucket_start(dt, seconds):
    """Align a naive-UTC timestamp to the start of its bucket."""
    if seconds >= 86400:                              # day buckets
        return dt.replace(hour=0, minute=0, second=0, microsecond=0)
    minutes = max(1, seconds // 60)
    return dt.replace(minute=(dt.minute // minutes) * minutes, second=0, microsecond=0)


@bp.get("/live-trend")
@api_login_required
def live_trend():
    """Findings per category over a rolling window - the live dashboard chart.

    Query params:
      window=hour|day|30d   (default hour)

    Only real rows are plotted. The buckets always end at "now", so a finding
    written a second ago already shows up in the newest point, and a category
    that stops producing findings falls away honestly as the window rolls on.
    """
    try:
        window = (request.args.get("window") or "hour").lower()
        if window not in LIVE_WINDOWS:
            window = "hour"
        bucket_seconds, bucket_count = LIVE_WINDOWS[window]

        # Rows store naive UTC (models.utcnow), so the cutoff is naive UTC too.
        now = datetime.now(timezone.utc).replace(tzinfo=None)
        current = _bucket_start(now, bucket_seconds)
        buckets = [current - timedelta(seconds=bucket_seconds * i)
                   for i in range(bucket_count - 1, -1, -1)]
        start = buckets[0]

        rows = (db.session.query(Vulnerability.created_at, Vulnerability.name)
                .join(Scan, Vulnerability.scan_id == Scan.id)
                .filter(Scan.user_id == user_id(),
                        Vulnerability.created_at >= start).all())

        index = {b: i for i, b in enumerate(buckets)}
        counts = defaultdict(lambda: defaultdict(int))
        labels = {}
        totals = defaultdict(int)
        for created_at, name in rows:
            if not created_at:
                continue
            pos = index.get(_bucket_start(created_at, bucket_seconds))
            if pos is None:                           # outside the window
                continue
            key, label = _type_bucket(name)
            counts[key][pos] += 1
            totals[key] += 1
            labels[key] = label

        ordered = sorted(totals.items(), key=lambda kv: kv[1], reverse=True)
        kept = ordered[:LIVE_MAX_SERIES]
        series = [{"key": key, "label": labels[key], "total": totals[key],
                   "data": [counts[key].get(i, 0) for i in range(len(buckets))]}
                  for key, _ in kept]
        events = sum(totals.values())
        scanning = db.session.query(Scan.id).filter(
            Scan.user_id == user_id(),
            Scan.status.in_((["pending", "running"]))).first() is not None

        return jsonify(
            window=window,
            bucket_seconds=bucket_seconds,
            buckets=[b.replace(tzinfo=timezone.utc).isoformat() for b in buckets],
            series=series,
            events=events,
            omitted=max(0, len(ordered) - len(kept)),
            scanning=scanning,
            generated_at=now.replace(tzinfo=timezone.utc).isoformat(),
            empty=not series,
        )
    except Exception as exc:
        return jsonify(error=f"Failed to compute live trend: {exc}"), 500


@bp.get("/sparklines")
@api_login_required
def sparklines_endpoint():
    try:
        return jsonify(sparklines=_sparklines())
    except Exception as exc:
        return jsonify(error=str(exc)), 500


def _sparklines():
    """Per-day finding counts for the last 14 days for mini charts."""
    rows = (db.session.query(func.date(Vulnerability.created_at), Vulnerability.severity,
                             func.count(Vulnerability.id))
            .join(Scan, Vulnerability.scan_id == Scan.id)
            .filter(Scan.user_id == user_id(),
                    Vulnerability.created_at >= func.date("now", "-14 day"))
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
    """Percentage change old -> new.

    Returns None when there is no baseline to compare against, so the UI shows
    "—" rather than a fabricated 100% increase over zero.
    """
    if not old:
        return None
    return round(100.0 * (new - old) / old, 1)
