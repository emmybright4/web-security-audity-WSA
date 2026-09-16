"""WSA database models."""
from datetime import datetime, timezone

from .extensions import db


def utcnow():
    return datetime.now(timezone.utc)


SEVERITY_ORDER = {"critical": 4, "high": 4, "medium": 3, "low": 2, "informational": 1, "info": 1}


class User(db.Model):
    __tablename__ = "users"

    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), default="IT Student")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    target_url = db.Column(db.String(2048), nullable=False)
    scan_type = db.Column(db.String(40), nullable=False, default="passive")
    status = db.Column(db.String(20), default="pending", nullable=False)  # pending|running|completed|failed|cancelled
    progress = db.Column(db.Integer, default=0, nullable=False)
    options = db.Column(db.PickleType, default=dict)  # engines + auth + policy settings
    current_step = db.Column(db.String(255), default="")
    error_message = db.Column(db.Text, default="")
    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    vulnerabilities = db.relationship("Vulnerability", backref="scan", lazy="dynamic",
                                      cascade="all, delete-orphan")
    reports = db.relationship("Report", backref="scan", lazy="dynamic",
                              cascade="all, delete-orphan")

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 1)
        return None

    def to_dict(self, include_counts=True):
        counts = {}
        if include_counts:
            counts = self.severity_counts()
        return {
            "id": self.id,
            "target_url": self.target_url,
            "scan_type": self.scan_type,
            "status": self.status,
            "progress": self.progress,
            "current_step": self.current_step,
            "error_message": self.error_message,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "duration_seconds": self.duration_seconds,
            "findings_count": self.vulnerabilities.count(),
            **counts,
        }

    def severity_counts(self):
        rows = (db.session.query(Vulnerability.severity, db.func.count(Vulnerability.id))
                .filter(Vulnerability.scan_id == self.id)
                .group_by(Vulnerability.severity).all())
        raw = {sev: cnt for sev, cnt in rows}
        # normalize aliases (zap uses "info", gosqli may use "critical")
        merged = {
            "high": raw.get("high", 0) + raw.get("critical", 0),
            "medium": raw.get("medium", 0),
            "low": raw.get("low", 0),
            "informational": raw.get("informational", 0) + raw.get("info", 0),
        }
        return merged


class Vulnerability(db.Model):
    __tablename__ = "vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="CASCADE"), nullable=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    severity = db.Column(db.String(20), default="informational", nullable=False, index=True)
    confidence = db.Column(db.String(20), default="medium")
    description = db.Column(db.Text, default="")
    evidence = db.Column(db.Text, default="")
    remediation = db.Column(db.Text, default="")
    target_url = db.Column(db.String(2048), default="")
    url = db.Column(db.String(2048), default="")  # exact endpoint
    detected_by = db.Column(db.String(60), default="WSA Built-in Scanner")
    status = db.Column(db.String(20), default="open", nullable=False)  # open|in_review|resolved|false_positive
    notes = db.Column(db.Text, default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "name": self.name,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description or "",
            "evidence": self.evidence or "",
            "remediation": self.remediation or "",
            "target_url": self.target_url or (self.scan.target_url if self.scan else ""),
            "url": self.url or "",
            "detected_by": self.detected_by,
            "status": self.status,
            "notes": self.notes or "",
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Report(db.Model):
    __tablename__ = "reports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="SET NULL"), nullable=True)
    report_name = db.Column(db.String(255), nullable=False)
    report_path = db.Column(db.String(1024), nullable=False)
    generated_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "report_name": self.report_name,
            "report_path": self.report_path,
            "generated_at": self.generated_at.isoformat() if self.generated_at else None,
        }


class ToolIntegration(db.Model):
    __tablename__ = "tool_integrations"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(80), unique=True, nullable=False)
    status = db.Column(db.String(30), default="not_configured")  # connected|disconnected|not_configured|error
    version = db.Column(db.String(60), default="")
    detail = db.Column(db.Text, default="")
    last_checked = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "status": self.status,
            "version": self.version or "",
            "detail": self.detail or "",
            "last_checked": self.last_checked.isoformat() if self.last_checked else None,
        }


class ScanTemplate(db.Model):
    __tablename__ = "scan_templates"

    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(120), nullable=False)
    description = db.Column(db.Text, default="")
    options = db.Column(db.PickleType, default=dict)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "name": self.name,
            "description": self.description or "",
            "options": self.options or {},
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class Setting(db.Model):
    __tablename__ = "settings"

    key = db.Column(db.String(80), primary_key=True)
    value = db.Column(db.PickleType, default="")
