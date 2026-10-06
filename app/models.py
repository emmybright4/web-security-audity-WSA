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
    email = db.Column(db.String(120), unique=True, nullable=True)
    phone_number = db.Column(db.String(20), unique=True, nullable=True, index=True)
    password_hash = db.Column(db.String(255), nullable=False)
    role = db.Column(db.String(40), default="IT Student")
    email_verified = db.Column(db.Boolean, default=False, nullable=False)
    phone_verified = db.Column(db.Boolean, default=False, nullable=False)
    primary_auth_method = db.Column(db.String(10), default="email", nullable=False)  # email|phone
    is_active = db.Column(db.Boolean, default=True, nullable=False)
    last_login_at = db.Column(db.DateTime, nullable=True)
    last_login_ip = db.Column(db.String(64), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def set_password(self, password):
        from werkzeug.security import generate_password_hash
        self.password_hash = generate_password_hash(password)

    def check_password(self, password):
        # "!" is the legacy placeholder for seeded rows without a real password
        if self.password_hash == "!":
            return False
        from werkzeug.security import check_password_hash
        return check_password_hash(self.password_hash, password)

    def verified_channels(self):
        """Verified contact channels, as (channel, destination) pairs."""
        pairs = []
        if self.email and self.email_verified:
            pairs.append(("email", self.email))
        if self.phone_number and self.phone_verified:
            pairs.append(("phone", self.phone_number))
        return pairs

    def to_dict(self):
        return {
            "id": self.id,
            "username": self.username,
            "email": self.email or "",
            "phone_number": self.phone_number or "",
            "role": self.role,
            "email_verified": bool(self.email_verified),
            "phone_verified": bool(self.phone_verified),
            "primary_auth_method": self.primary_auth_method or "email",
            "initials": "".join(w[0] for w in (self.username or "").split()[:2]).upper()
                       or (self.username or "?")[:2].upper(),
        }


# =====================================================================
# Verification / OTP
# =====================================================================

CHANNEL_EMAIL = "email"
CHANNEL_PHONE = "phone"

PURPOSE_ACCOUNT_VERIFICATION = "account_verification"
PURPOSE_PASSWORD_RESET = "password_reset"
PURPOSE_LOGIN_VERIFICATION = "login_verification"
PURPOSE_RECIPIENT_VERIFICATION = "recipient_verification"


class VerificationCode(db.Model):
    """A single six-digit challenge. Only the hash is ever persisted."""

    __tablename__ = "verification_codes"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=True, index=True)
    recipient_id = db.Column(db.Integer, db.ForeignKey("security_recipients.id", ondelete="CASCADE"),
                             nullable=True, index=True)
    channel = db.Column(db.String(10), nullable=False)  # email|phone
    purpose = db.Column(db.String(32), nullable=False, index=True)
    destination = db.Column(db.String(2048), nullable=False)
    code_hash = db.Column(db.String(255), nullable=False)
    expires_at = db.Column(db.DateTime, nullable=False)
    attempt_count = db.Column(db.Integer, default=0, nullable=False)
    max_attempts = db.Column(db.Integer, default=5, nullable=False)
    used = db.Column(db.Boolean, default=False, nullable=False)
    used_at = db.Column(db.DateTime, nullable=True)
    invalidated_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)

    def is_active(self, now=None):
        now = now or utcnow()
        return not (self.used or self.invalidated_at) and _aware(self.expires_at) > now

    def is_expired(self, now=None):
        return _aware(self.expires_at) <= (now or utcnow())

    def attempts_left(self):
        return max(0, int(self.max_attempts) - int(self.attempt_count))

    def to_dict(self):
        return {
            "id": self.id,
            "channel": self.channel,
            "purpose": self.purpose,
            "destination": self.destination,
            "expires_at": self.expires_at.isoformat() if self.expires_at else None,
            "attempt_count": self.attempt_count,
            "attempts_left": self.attempts_left(),
            "max_attempts": self.max_attempts,
            "used": bool(self.used),
            "expired": self.is_expired(),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


def _aware(value):
    """SQLite drops tzinfo on read; treat naive stamps as UTC."""
    if value is None:
        return utcnow()
    return value if value.tzinfo else value.replace(tzinfo=timezone.utc)


class SecurityRecipient(db.Model):
    """An authorised address that may receive sensitive WSA reports."""

    __tablename__ = "security_recipients"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, index=True)
    email = db.Column(db.String(120), nullable=False)
    label = db.Column(db.String(80), default="Security Team")
    verified = db.Column(db.Boolean, default=False, nullable=False)
    verified_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    __table_args__ = (db.UniqueConstraint("user_id", "email", name="uq_recipient_user_email"),)

    def to_dict(self):
        return {
            "id": self.id,
            "email": self.email,
            "label": self.label or "",
            "verified": bool(self.verified),
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class NotificationPreference(db.Model):
    """Per-user opt-in switches for every email and SMS event type."""

    __tablename__ = "notification_preferences"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="CASCADE"),
                        nullable=False, unique=True)
    email_events = db.Column(db.JSON, default=dict, nullable=False)
    sms_events = db.Column(db.JSON, default=dict, nullable=False)
    updated_at = db.Column(db.DateTime, default=utcnow, onupdate=utcnow, nullable=False)

    def to_dict(self):
        return {"email": dict(self.email_events or {}),
                "sms": dict(self.sms_events or {})}


class EmailLog(db.Model):
    __tablename__ = "email_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True, index=True)
    recipient = db.Column(db.String(320), nullable=False)
    email_type = db.Column(db.String(40), nullable=False, index=True)
    subject = db.Column(db.String(255), default="")
    related_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="SET NULL"),
                                nullable=True, index=True)
    status = db.Column(db.String(20), default="pending", nullable=False)  # sent|pending|failed
    provider_message_id = db.Column(db.String(255), default="")
    error_message = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    sent_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        return {
            "id": self.id,
            "user_id": self.user_id,
            "recipient": self.recipient,
            "email_type": self.email_type,
            "subject": self.subject or "",
            "related_scan_id": self.related_scan_id,
            "status": self.status,
            "error_message": self.error_message or "",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
        }


class SmsLog(db.Model):
    __tablename__ = "sms_logs"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True, index=True)
    phone_number = db.Column(db.String(20), nullable=False)
    sms_type = db.Column(db.String(40), nullable=False, index=True)
    purpose = db.Column(db.String(32), default="")
    related_scan_id = db.Column(db.Integer, db.ForeignKey("scans.id", ondelete="SET NULL"),
                                nullable=True, index=True)
    status = db.Column(db.String(20), default="pending", nullable=False)
    provider_message_id = db.Column(db.String(255), default="")
    error_message = db.Column(db.String(500), default="")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False, index=True)
    sent_at = db.Column(db.DateTime, nullable=True)

    def to_dict(self):
        from .services.phone_service import mask_phone
        return {
            "id": self.id,
            "user_id": self.user_id,
            "phone_number": mask_phone(self.phone_number),
            "sms_type": self.sms_type,
            "purpose": self.purpose or "",
            "related_scan_id": self.related_scan_id,
            "status": self.status,
            "error_message": self.error_message or "",
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "sent_at": self.sent_at.isoformat() if self.sent_at else None,
        }


class Scan(db.Model):
    __tablename__ = "scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True, index=True)
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

    vulnerabilities = db.relationship("Vulnerability", back_populates="scan", lazy="dynamic",
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
    scan = db.relationship("Scan", back_populates="vulnerabilities")
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


# =====================================================================
# IP / Network Scanning models
# =====================================================================

class IPScan(db.Model):
    __tablename__ = "ip_scans"

    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("users.id", ondelete="SET NULL"),
                        nullable=True, index=True)
    target = db.Column(db.String(512), nullable=False)  # IP, range, or CIDR
    scan_profile = db.Column(db.String(40), nullable=False, default="quick")
    # quick_discovery | standard_network | full_vulnerability | custom
    status = db.Column(db.String(20), default="pending", nullable=False)
    # pending|running|completed|failed|cancelled
    progress = db.Column(db.Integer, default=0, nullable=False)
    current_step = db.Column(db.String(255), default="")
    error_message = db.Column(db.Text, default="")
    options = db.Column(db.PickleType, default=dict)
    scan_number = db.Column(db.Integer, default=0)  # sequential scan #

    # Live counters updated during scan
    hosts_discovered = db.Column(db.Integer, default=0)
    open_ports_count = db.Column(db.Integer, default=0)
    services_detected = db.Column(db.Integer, default=0)
    vulnerabilities_count = db.Column(db.Integer, default=0)
    critical_count = db.Column(db.Integer, default=0)
    high_count = db.Column(db.Integer, default=0)
    medium_count = db.Column(db.Integer, default=0)
    low_count = db.Column(db.Integer, default=0)
    informational_count = db.Column(db.Integer, default=0)

    started_at = db.Column(db.DateTime, nullable=True)
    completed_at = db.Column(db.DateTime, nullable=True)
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    hosts = db.relationship("IPScanHost", backref="scan", lazy="dynamic",
                             cascade="all, delete-orphan")
    vulnerabilities = db.relationship("IPScanVulnerability", backref="scan", lazy="dynamic",
                                       cascade="all, delete-orphan")

    @property
    def duration_seconds(self):
        if self.started_at and self.completed_at:
            return round((self.completed_at - self.started_at).total_seconds(), 1)
        return None

    def to_dict(self):
        return {
            "id": self.id,
            "target": self.target,
            "scan_profile": self.scan_profile,
            "status": self.status,
            "progress": self.progress,
            "current_step": self.current_step,
            "error_message": self.error_message,
            "options": self.options or {},
            "scan_number": self.scan_number,
            "hosts_discovered": self.hosts_discovered,
            "open_ports_count": self.open_ports_count,
            "services_detected": self.services_detected,
            "vulnerabilities_count": self.vulnerabilities_count,
            "critical_count": self.critical_count,
            "high_count": self.high_count,
            "medium_count": self.medium_count,
            "low_count": self.low_count,
            "informational_count": self.informational_count,
            "started_at": self.started_at.isoformat() if self.started_at else None,
            "completed_at": self.completed_at.isoformat() if self.completed_at else None,
            "created_at": self.created_at.isoformat() if self.created_at else None,
            "duration_seconds": self.duration_seconds,
        }


class IPScanHost(db.Model):
    __tablename__ = "ip_scan_hosts"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("ip_scans.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    ip_address = db.Column(db.String(64), nullable=False)
    hostname = db.Column(db.String(255), default="")
    os_detection = db.Column(db.String(128), default="")
    mac_address = db.Column(db.String(32), default="")
    status = db.Column(db.String(20), default="up")  # up|down|filtered
    open_ports_count = db.Column(db.Integer, default=0)
    services_count = db.Column(db.Integer, default=0)
    vulnerabilities_count = db.Column(db.Integer, default=0)
    risk_level = db.Column(db.String(20), default="low")  # critical|high|medium|low|none
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    ports = db.relationship("IPScanPort", backref="host", lazy="dynamic",
                             cascade="all, delete-orphan")
    vulns = db.relationship("IPScanVulnerability", backref="host", lazy="dynamic",
                             cascade="all, delete-orphan")

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "ip_address": self.ip_address,
            "hostname": self.hostname or "",
            "os_detection": self.os_detection or "",
            "mac_address": self.mac_address or "",
            "status": self.status,
            "open_ports_count": self.open_ports_count,
            "services_count": self.services_count,
            "vulnerabilities_count": self.vulnerabilities_count,
            "risk_level": self.risk_level,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IPScanPort(db.Model):
    __tablename__ = "ip_scan_ports"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("ip_scans.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    host_id = db.Column(db.Integer, db.ForeignKey("ip_scan_hosts.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    port_number = db.Column(db.Integer, nullable=False)
    protocol = db.Column(db.String(10), default="tcp")
    service = db.Column(db.String(80), default="")
    version = db.Column(db.String(128), default="")
    banner = db.Column(db.Text, default="")
    state = db.Column(db.String(20), default="open")  # open|closed|filtered
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "host_id": self.host_id,
            "port_number": self.port_number,
            "protocol": self.protocol,
            "service": self.service or "",
            "version": self.version or "",
            "banner": self.banner or "",
            "state": self.state,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }


class IPScanVulnerability(db.Model):
    __tablename__ = "ip_scan_vulnerabilities"

    id = db.Column(db.Integer, primary_key=True)
    scan_id = db.Column(db.Integer, db.ForeignKey("ip_scans.id", ondelete="CASCADE"),
                         nullable=False, index=True)
    host_id = db.Column(db.Integer, db.ForeignKey("ip_scan_hosts.id", ondelete="CASCADE"),
                         nullable=True, index=True)
    name = db.Column(db.String(255), nullable=False)
    vuln_type = db.Column(db.String(80), default="")
    # open_ports, insecure_services, outdated_software, cve, ssl_tls,
    # misconfig, auth_weakness, info_disclosure, smb_issues,
    # remote_service, os_host
    severity = db.Column(db.String(20), default="informational", nullable=False)
    confidence = db.Column(db.String(20), default="medium")
    host_ip = db.Column(db.String(64), default="")
    port = db.Column(db.Integer, nullable=True)
    service = db.Column(db.String(80), default="")
    cve_id = db.Column(db.String(40), default="")
    cvss_score = db.Column(db.Float, nullable=True)
    affected_software = db.Column(db.String(255), default="")
    description = db.Column(db.Text, default="")
    evidence = db.Column(db.Text, default="")
    recommendation = db.Column(db.Text, default="")
    status = db.Column(db.String(20), default="open")
    detected_by = db.Column(db.String(60), default="WSA IP Scanner")
    created_at = db.Column(db.DateTime, default=utcnow, nullable=False)

    def to_dict(self):
        return {
            "id": self.id,
            "scan_id": self.scan_id,
            "host_id": self.host_id,
            "name": self.name,
            "vuln_type": self.vuln_type or "",
            "severity": self.severity,
            "confidence": self.confidence,
            "host_ip": self.host_ip or "",
            "port": self.port,
            "service": self.service or "",
            "cve_id": self.cve_id or "",
            "cvss_score": self.cvss_score,
            "affected_software": self.affected_software or "",
            "description": self.description or "",
            "evidence": self.evidence or "",
            "recommendation": self.recommendation or "",
            "status": self.status,
            "detected_by": self.detected_by,
            "created_at": self.created_at.isoformat() if self.created_at else None,
        }
